"""Engine E2 tests: protocol trees for supported and damaged frames."""

from __future__ import annotations

from helpers import (
    arp_frame,
    dns_query,
    ethernet,
    http_request,
    tcp_frame,
    udp_frame,
    unknown_frame,
)

from backend.e2_dissection import ProtocolDissector
from backend.models import Packet


def _packet(frame: bytes, index: int = 0) -> Packet:
    return Packet(index=index, timestamp=1.0, length=len(frame), raw_bytes=frame)


def _names(frame: bytes) -> list[str]:
    decoded = ProtocolDissector().dissect_one(_packet(frame))
    return [layer.name for layer in decoded.layers]


def test_decodes_ethernet_ipv4_tcp():
    decoded = ProtocolDissector().dissect_one(_packet(tcp_frame(dport=443)))

    assert [layer.name for layer in decoded.layers] == ["Ethernet", "IPv4", "TCP"]
    ip_layer, tcp_layer = decoded.layers[1], decoded.layers[2]
    assert ip_layer.fields["src"] == "10.0.0.1"
    assert ip_layer.fields["dst"] == "10.0.0.2"
    assert ip_layer.fields["protocol"] == 6
    assert tcp_layer.fields["src_port"] == 12345
    assert tcp_layer.fields["dst_port"] == 443
    assert decoded.packet_index == 0


def test_decodes_udp_dns():
    frame = udp_frame(dport=53, payload=dns_query("example.com"))

    decoded = ProtocolDissector().dissect_one(_packet(frame))

    assert [layer.name for layer in decoded.layers] == [
        "Ethernet",
        "IPv4",
        "UDP",
        "DNS",
    ]
    dns_layer = decoded.layers[3]
    assert dns_layer.fields["questions"][0]["name"] == "example.com"
    assert dns_layer.fields["response"] is False


def test_decodes_http_request():
    frame = tcp_frame(dport=80, payload=http_request())

    decoded = ProtocolDissector().dissect_one(_packet(frame))

    assert [layer.name for layer in decoded.layers] == [
        "Ethernet",
        "IPv4",
        "TCP",
        "HTTP",
    ]
    assert decoded.layers[3].fields["start_line"] == "GET /index.html HTTP/1.1"
    assert decoded.layers[3].fields["headers"]["host"] == "example.com"


def test_arp_has_no_network_layer():
    decoded = ProtocolDissector().dissect_one(_packet(arp_frame()))

    assert [layer.name for layer in decoded.layers] == ["Ethernet", "ARP"]
    assert decoded.layers[1].fields["src_ip"] == "10.0.0.1"
    assert decoded.layers[1].fields["dst_ip"] == "10.0.0.99"


def test_unknown_ethertype_is_kept_as_payload():
    frame = unknown_frame()

    decoded = ProtocolDissector().dissect_one(_packet(frame))

    assert [layer.name for layer in decoded.layers] == ["Ethernet", "Payload"]
    assert decoded.layers[1].undecoded_bytes == b"\xde\xad\xbe\xef"


def test_truncated_frame_does_not_raise():
    decoded = ProtocolDissector().dissect_one(_packet(b"\xaa\xbb"))

    assert decoded.layers[0].name == "Ethernet"
    assert decoded.layers[0].undecoded_bytes == b"\xaa\xbb"


def test_malformed_ip_header_is_marked_and_walk_stops():
    frame = ethernet(b"\x45\x00\x00", 0x0800)

    decoded = ProtocolDissector().dissect_one(_packet(frame))

    assert [layer.name for layer in decoded.layers] == ["Ethernet", "IPv4"]
    assert decoded.layers[1].fields["truncated"] is True


def test_bad_packet_never_stops_the_batch():
    good, bad = tcp_frame(), b"\x00\x01"

    decoded = ProtocolDissector().dissect([_packet(good, 0), _packet(bad, 1)])

    assert len(decoded) == 2
    assert [layer.name for layer in decoded[0].layers][-1] == "TCP"
    assert decoded[1].packet_index == 1


def test_non_http_payload_on_port_80_is_preserved():
    frame = tcp_frame(dport=80, payload=b"\x16\x03\x01\x00\xde\xad")

    decoded = ProtocolDissector().dissect_one(_packet(frame))

    assert [layer.name for layer in decoded.layers] == [
        "Ethernet",
        "IPv4",
        "TCP",
        "Payload",
    ]
    assert decoded.layers[3].undecoded_bytes.startswith(b"\x16\x03")


def test_dissector_names_are_registered():
    registry = ProtocolDissector().registry
    names = {
        name
        for table in registry._namespaces.values()
        for name, _handler in table.values()
    }

    expected = {"Ethernet", "IPv4", "IPv6", "TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP"}
    assert expected <= names
