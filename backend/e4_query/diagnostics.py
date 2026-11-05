"""E4 — Deterministic diagnostic rule engine (Phase 5).

Four rules evaluated against a window of CorrelationRecords:

1. PACKET_LOSS    — unmatched records exceed threshold
2. BUFFERBLOAT    — sustained rising ΔT trend
3. APP_FREEZE     — high average ΔT (server think-time)
4. DNS_EXFIL      — DNS query entropy above 4.2 bits

Each rule returns a DiagnosticAlert or None.  The engine never raises —
a bad record is skipped, not a crash.
"""

from __future__ import annotations

import time
from collections.abc import Sequence

from backend.models import CorrelationRecord, DecodedPacket, DiagnosticAlert

# ──────────────────────────────────────────────────────────────────────────────
# Thresholds (all configurable)
# ──────────────────────────────────────────────────────────────────────────────
LOSS_THRESHOLD       = 0.05   # 5 % unmatched → PACKET_LOSS
BUFFERBLOAT_SLOPE_MS = 0.5    # ΔT rising by > 0.5 ms/packet → BUFFERBLOAT
APP_FREEZE_MS        = 150.0  # avg ΔT > 150 ms → APP_FREEZE
DNS_ENTROPY_THRESH   = 4.2    # H(X) > 4.2 → DNS_EXFIL_SUSPECTED
MIN_RECORDS          = 5      # need at least this many records to fire


# ──────────────────────────────────────────────────────────────────────────────
# Individual rules
# ──────────────────────────────────────────────────────────────────────────────

def rule_packet_loss(records: Sequence[CorrelationRecord]) -> DiagnosticAlert | None:
    """Fire when ≥ 5 % of packets are unmatched within the window."""
    if len(records) < MIN_RECORDS:
        return None

    unmatched = [r for r in records if r.match_state in ("unmatched", "late")]
    loss_rate = len(unmatched) / len(records)

    if loss_rate < LOSS_THRESHOLD:
        return None

    fps = [r.fingerprint for r in unmatched[:10]]
    return DiagnosticAlert(
        category="PACKET_LOSS",
        severity="critical" if loss_rate > 0.20 else "warning",
        confidence="high",
        detected_at_ns=time.time_ns(),
        recommended_action=(
            "Check physical cable / link on the path between Probe 1 and Probe 2. "
            "Verify switch/router forwarding tables. "
            "If wireless: check signal strength and channel congestion."
        ),
        evidence_refs=fps,
        metrics={
            "loss_rate": round(loss_rate, 4),
            "unmatched_count": float(len(unmatched)),
            "total_count": float(len(records)),
        },
    )


def rule_bufferbloat(records: Sequence[CorrelationRecord]) -> DiagnosticAlert | None:
    """Fire when ΔT shows a sustained rising trend (bufferbloat signature)."""
    delays = [
        r.delay_ns / 1_000_000  # convert to ms
        for r in records
        if r.delay_ns is not None and r.match_state == "matched"
    ]
    if len(delays) < MIN_RECORDS:
        return None

    # Linear slope via simple least-squares
    n   = len(delays)
    xs  = list(range(n))
    x_mean = (n - 1) / 2
    y_mean = sum(delays) / n
    num   = sum((xs[i] - x_mean) * (delays[i] - y_mean) for i in range(n))
    denom = sum((xs[i] - x_mean) ** 2 for i in range(n))
    slope = num / denom if denom else 0.0  # ms per packet

    if slope < BUFFERBLOAT_SLOPE_MS:
        return None

    fps = [r.fingerprint for r in records if r.delay_ns is not None][:10]
    return DiagnosticAlert(
        category="BUFFERBLOAT",
        severity="warning",
        confidence="medium",
        detected_at_ns=time.time_ns(),
        recommended_action=(
            "Enable FQ-CoDel or CAKE AQM on the router between the two probes. "
            "Check router queue depth and buffer sizes. "
            "Consider traffic shaping if a single flow is dominating the link."
        ),
        evidence_refs=fps,
        metrics={
            "delay_slope_ms_per_pkt": round(slope, 4),
            "avg_delay_ms": round(y_mean, 4),
            "min_delay_ms": round(min(delays), 4),
            "max_delay_ms": round(max(delays), 4),
        },
    )


def rule_app_freeze(records: Sequence[CorrelationRecord]) -> DiagnosticAlert | None:
    """Fire when average one-way delay exceeds the APP_FREEZE threshold."""
    delays = [
        r.delay_ns / 1_000_000
        for r in records
        if r.delay_ns is not None and r.match_state == "matched"
    ]
    if len(delays) < MIN_RECORDS:
        return None

    avg_ms = sum(delays) / len(delays)
    if avg_ms < APP_FREEZE_MS:
        return None

    fps = [r.fingerprint for r in records if r.delay_ns is not None][:10]
    return DiagnosticAlert(
        category="APP_FREEZE",
        severity="warning" if avg_ms < 500 else "critical",
        confidence="medium",
        detected_at_ns=time.time_ns(),
        recommended_action=(
            "High one-way delay detected at the server/gateway probe. "
            "Check server CPU, memory and disk I/O — high server think-time "
            "causes application-visible freezes. "
            "Profile the application layer and check for database lock contention."
        ),
        evidence_refs=fps,
        metrics={
            "avg_delay_ms": round(avg_ms, 4),
            "max_delay_ms": round(max(delays), 4),
            "sample_count": float(len(delays)),
        },
    )


def rule_dns_exfil(decoded_packets: Sequence[DecodedPacket]) -> DiagnosticAlert | None:
    """Fire when any DNS query name has Shannon entropy > 4.2 bits.

    Per the data contract: confidence is always low/medium — this is a
    heuristic signal, never proof of data theft.
    """
    suspects: list[tuple[int, float]] = []  # (packet_index, entropy)
    for dec in decoded_packets:
        if dec.dns_entropy is not None and dec.dns_entropy > DNS_ENTROPY_THRESH:
            suspects.append((dec.packet_index, dec.dns_entropy))

    if not suspects:
        return None

    fps = [dec.fingerprint.value for dec in decoded_packets
           if dec.fingerprint and dec.dns_entropy is not None
           and dec.dns_entropy > DNS_ENTROPY_THRESH]

    max_entropy = max(h for _, h in suspects)
    return DiagnosticAlert(
        category="DNS_EXFIL_SUSPECTED",
        severity="warning",
        confidence="low",
        detected_at_ns=time.time_ns(),
        recommended_action=(
            "One or more DNS queries have unusually high Shannon entropy "
            f"(H > {DNS_ENTROPY_THRESH} bits), which may indicate DNS tunnelling "
            "or data exfiltration. "
            "Inspect the flagged domain names manually. "
            "Block the domain via firewall / RPZ if confirmed malicious. "
            "Note: high-entropy legitimate subdomains (CDN, DKIM) can also trigger this."
        ),
        evidence_refs=fps[:10],
        metrics={
            "suspect_count": float(len(suspects)),
            "max_entropy": round(max_entropy, 4),
            "threshold": DNS_ENTROPY_THRESH,
        },
    )


# ──────────────────────────────────────────────────────────────────────────────
# Unified runner
# ──────────────────────────────────────────────────────────────────────────────

def run_diagnostics(
    records: Sequence[CorrelationRecord],
    decoded_packets: Sequence[DecodedPacket] | None = None,
) -> list[DiagnosticAlert]:
    """Run all four rules; return list of alerts (may be empty).

    Args:
        records:         CorrelationRecords from E3 (current window).
        decoded_packets: DecodedPackets from E2 (for DNS rule).
    """
    alerts: list[DiagnosticAlert] = []

    for rule in (rule_packet_loss, rule_bufferbloat, rule_app_freeze):
        try:
            alert = rule(records)
            if alert:
                alerts.append(alert)
        except Exception:  # noqa: BLE001
            pass  # a bad rule never stops the others

    if decoded_packets:
        try:
            alert = rule_dns_exfil(decoded_packets)
            if alert:
                alerts.append(alert)
        except Exception:  # noqa: BLE001
            pass

    return alerts
