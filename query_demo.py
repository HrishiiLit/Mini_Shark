import json
import urllib.request

BASE = "http://127.0.0.1:8000"


def get(path):
    with urllib.request.urlopen(BASE + path) as r:
        return json.loads(r.read())


def post(path, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        BASE + path,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"ERROR": e.code, "detail": e.read().decode()}


SEP = "=" * 60


def show(title, data):
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)
    print(json.dumps(data, indent=2))


# filter fields available: bytes, duration, flow.byte_count, flow.id,
# flow.packet_count, ip.dst, ip.src, packets, port, protocol, tcp.port, udp.port

show(
    'POST /query  protocol=="TCP"  (all TCP flows)',
    post("/query", {"filter": 'protocol == "TCP"', "capture_id": 1}),
)

show(
    'POST /query  protocol=="UDP"  (all DNS flows)',
    post("/query", {"filter": 'protocol == "UDP"', "capture_id": 1}),
)

show(
    'POST /query  ip.dst=="8.8.8.8"  (flows to Google DNS)',
    post("/query", {"filter": 'ip.dst == "8.8.8.8"', "capture_id": 1}),
)

show(
    "POST /query  tcp.port==443  (HTTPS)",
    post("/query", {"filter": "tcp.port == 443", "capture_id": 1}),
)

show(
    "POST /query  tcp.port==80  (HTTP)",
    post("/query", {"filter": "tcp.port == 80", "capture_id": 1}),
)

show(
    "POST /query  flow.packet_count>1  (multi-packet flows only)",
    post("/query", {"filter": "flow.packet_count > 1", "capture_id": 1}),
)

show(
    "GET /captures/1/packets/5/tree  (suspicious DNS exfil name)",
    get("/captures/1/packets/5/tree"),
)

show(
    "GET /captures/1/packets/6/tree  (HTTP GET /index.html)",
    get("/captures/1/packets/6/tree"),
)
