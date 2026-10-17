# Mini Shark — Network Traffic Analyzer and Protocol Analysis System

**Team 07** · Guide: Pooja Shettar · Default branch: `master` · Latest tag: `v0.1-phase1`

Mini Shark is a Wireshark-style analyzer for PCAP/PCAPNG captures. A Python
service loads a capture, dissects every packet into a protocol tree, groups
packets into five-tuple flows, and answers queries about them through a
FastAPI HTTP API.

## Where the project stands

**Phase 1 (foundation, contracts, test data) is complete. Phase 2 (E1 + E2)
has not started yet.**

| Area | State |
| --- | --- |
| Data contract — `backend/models.py` | Done: frozen dataclasses `Packet`, `Layer`, `DecodedPacket`, `Flow` |
| Engine interfaces — `backend/interfaces.py` | Done: abstract base classes `EngineE1`–`EngineE4` |
| HTTP service — `backend/main.py` | Skeleton: FastAPI app with `GET /health` only |
| Engine implementations — `backend/e1_capture`, `e2_dissection`, `e3_flows`, `e4_query`, `api` | Empty placeholders, no logic yet |
| Test fixtures — `tests/data/` | Done: 10 captures (tcp, udp, dns, http, icmp, arp, pcapng, empty, corrupt, 100 MB) |
| Expected outputs — `tests/expected/` | Placeholders (`{}`); real values are generated with tshark in Phase 2 |
| Test cases | None yet — `pytest` collects nothing, which is expected at this stage |
| SQLite storage, API routes, frontend | Not started; drafts live in `docs/api_routes.md` |

## The four engines

| Engine | Responsibility | Owner | Status |
| --- | --- | --- | --- |
| E1 | Packet & Frame Processing — PCAP/PCAPNG loading, packet records | Jana
ki | Not started |
| E2 | Protocol Dissection — protocol identification, header parsing, tree | Chhavi Mishra | Not started |
| E3 | Flow & Traffic Analysis — five-tuple flows, statistics | Hrishikesh | Not started |
| E4 | Traffic Query & Reporting — storage, filter/query engine | Vaibhav Kumar | Not started |

Engines only talk to each other through the data contract, so each one can be
built and tested in isolation against the fixtures in `tests/data/`.

## Repository layout

```
Mini_Shark/
├── backend/
│   ├── main.py          # FastAPI entrypoint (GET /health)
│   ├── models.py        # shared dataclasses: Packet, Layer, DecodedPacket, Flow
│   ├── interfaces.py    # abstract EngineE1–EngineE4
│   ├── e1_capture/      # E1 (planned)
│   ├── e2_dissection/   # E2 (planned)
│   ├── e3_flows/        # E3 (planned)
│   ├── e4_query/        # E4 (planned)
│   └── api/             # HTTP routes (planned)
├── tests/
│   ├── data/            # controlled PCAP/PCAPNG fixtures
│   └── expected/        # expected analysis outputs
├── docs/                # this README, plan, contract, API draft, contributing guide
├── .github/workflows/   # CI: pre-commit (ruff, black) + pytest
├── pyproject.toml       # project metadata, ruff/black/pytest config
├── requirements.txt     # dpkt, fastapi, uvicorn, sqlalchemy
└── run.sh               # create venv, install deps, start the dev server
```

## Getting started

**Prerequisites:** Python 3.11 or newer, Git.

```bash
git clone https://github.com/HrishiiLit/Mini_Shark.git
cd Mini_Shark
./run.sh          # creates .venv, installs requirements.txt, runs uvicorn --reload
```

`run.sh` targets Git Bash / WSL / Linux. On Windows PowerShell do the same
steps manually:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn backend.main:app --reload
```

Verify the service:

```bash
curl http://127.0.0.1:8000/health     # → {"status":"ok"}
```

### Quality checks

```bash
pytest                    # no test cases yet; exits 5 ("no tests collected")
ruff check .              # lint
black .                   # format
pre-commit run --all-files
```

CI (`.github/workflows/ci.yml`) runs pre-commit (ruff + black) and pytest on
every push and pull request.

## Documentation

| Document | Contents |
| --- | --- |
| `docs/implementation.md` | Six-phase plan: tasks, owners, durations, exit criteria, release tags |
| `docs/data_contract.md` | Field-by-field description of the shared types |
| `docs/api_routes.md` | Draft of the endpoints to implement in Phase 5 |
| `docs/CONTRIBUTING.md` | Branch naming, Conventional Commits, PR review rules |

## Roadmap

| Phase | Scope | Tag |
| --- | --- | --- |
| 1 | Foundation, contracts, test data | `v0.1-phase1` ✅ |
| 2 | Capture ingestion and protocol dissection (E1 + E2) | `v0.2-phase2` |
| 3 | Flow correlation and traffic statistics (E3) | `v0.3-phase3` |
| 4 | Storage and query engine (E4 backend) | `v0.4-phase4` |
| 5 | API layer and web interface | `v0.5-phase5` |
| 6 | Integration testing, hardening, documentation, demo | `v1.0` |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for branch naming, commit message
conventions, and the pull-request checklist. In short: branch off `master`,
use Conventional Commits, keep CI green, get one review.
