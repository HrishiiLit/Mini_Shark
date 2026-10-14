# Data Contract

The four engines share a strict data contract defined in `backend/models.py`.

## Packet (E1 Output)
- **index**: `int` – sequential packet number (starting at 0)
- **timestamp**: `float` – epoch seconds (or nanoseconds as float)
- **length**: `int` – total size in bytes
- **raw_bytes**: `bytes` – raw frame data

## DecodedPacket (E2 Output)
- **packet_index**: `int` – reference to the original `Packet.index`
- **layers**: `list[Layer]` – ordered protocol layers from link to application

### Layer
- **name**: `str` – protocol name (e.g. "Ethernet", "IPv4")
- **fields**: `dict[str, Any]` – parsed header fields
- **undecoded_bytes**: `bytes` – any remaining bytes that could not be parsed

## Flow (E3 Output)
- **flow_id**: `int` – unique identifier for the flow
- **five_tuple**: `tuple(src_ip, dst_ip, src_port, dst_port, protocol)`
- **packet_indices**: `list[int]` – indices of packets belonging to this flow
- **packet_count**: `int` – derived from `len(packet_indices)`
- **byte_count**: `int` – total bytes of all packets in the flow
- **start_ts** / **end_ts** / **duration**: timestamps derived from packet data

All engines must **never drop** packets that cannot be grouped; they go into an "ungrouped" bucket.
