# API Route Draft (Phase 1)

The FastAPI backend will expose the following endpoints once implemented:

- `POST /captures` – upload a PCAP/PCAPNG file, trigger analysis pipeline (E1→E4)
- `GET /captures/{capture_id}` – retrieve capture metadata (size, status, timestamps)
- `GET /captures/{capture_id}/packets` – paginated list of `Packet` objects
- `GET /captures/{capture_id}/packets/{packet_index}` – detailed packet info, raw bytes
- `GET /captures/{capture_id}/packets/{packet_index}/tree` – protocol tree (`DecodedPacket`)
- `GET /captures/{capture_id}/flows` – list of flows (`Flow` objects)
- `GET /captures/{capture_id}/flows/{flow_id}` – flow detail with packet indices
- `GET /captures/{capture_id}/statistics` – per‑protocol and per‑flow aggregates
- `POST /query` – filtered query language (e.g. `ip.src == "10.0.0.1" && tcp.port == 443`)

All endpoints will return JSON with proper `200`, `400`, `404`, and `422` status codes.
