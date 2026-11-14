# The Pre-Verdict Emulator

A hostile-feeling local range for the Pre-Verdict Sprint: vulnerable
apps behind a real WAF, rate limiter and fail2ban, with a monitoring
dashboard over the shared logs. Everything is local. No real targets,
ever — that is the point of a rehearsal.

## Endpoints

| Service | URL | Notes |
|---|---|---|
| juice-shop | http://localhost:3000 | vulnerable app (open) |
| dvwa | http://localhost:8080 | vulnerable app (admin/password) |
| custom-api | http://localhost:9000 | custom training API |
| waf | http://localhost:80 | juice-shop behind ModSecurity CRS, paranoia 2 |
| rate-limiter | http://localhost:8000 | juice-shop behind 5 r/s + burst 10 |
| monitoring | http://localhost:9090 | logs dashboard (`/api/stats` for JSON) |

## Usage

```bash
./scripts/start.sh        # up + endpoint map
./scripts/reset.sh        # full teardown (incl. volumes), fresh logs, up
./scripts/stop.sh         # down
./scripts/analyze-logs.py # attack report from the shared logs
python emulator_cli.py targets   # endpoint table
python emulator_cli.py status    # which services are up
python emulator_cli.py analyze   # same report via the CLI
```

Requires Docker. Without it, `start/stop/reset/logs` fail cleanly and
`status` reports the emulator as down.

## Layout

`docker-compose.yml` wires seven services on one bridge network.
`configs/` holds the WAF (engine on, paranoia 2, CRS included), the
rate-limiter (5 r/s, burst 10, 429 on excess) and the monitoring
config. `monitoring/nginx-logs/` is the shared log directory every
service reads and writes; `logparse.py` turns those logs into the
attack report used by both `scripts/analyze-logs.py` and the CLI.

## Tests

```bash
python -m pytest tests/ -q    # 27 tests
```

Structural, log-analysis and CLI tests always run. Anything needing
the live stack skips with a clear reason when Docker is absent.
