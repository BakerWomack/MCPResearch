# MCPResearch

Measures a TOCTOU window in an MCP-backed document workflow. A file is scanned,
marked safe, then read again by an LLM agent. An attacker overwrites the blob
between those two reads. Three architectures are compared.

| config | difference |
|---|---|
| `BaseLine` | agent reads the document as a tool call after inference; nothing re-verifies the bytes |
| `Tight` | server reads once before inference and inlines it in the prompt; `read_document` is not a tool |
| `Secure` | agent re-hashes the bytes it received against the scanner's seal; mismatch is rejected |

## Requirements

Docker Desktop, Ollama with `ollama pull qwen3:latest`, and `pip install httpx matplotlib`.
Only one config runs at a time: all three bind ports 8010, 9000, 9001, 3000, 5432.

## Run

```bash
./run_sweep.sh --dry-run          # check readiness, start nothing
./run_sweep.sh                    # all three configs, ~6 h
./run_sweep.sh --detached         # same, survives the terminal closing
./run_sweep.sh --configs Tight    # one config
```

PowerShell equivalents: `.\run_sweep.ps1 -DryRun`, `-Detached`, `-Configs Tight`.

Both wrap `sweep_all.py`, which per config wipes the volumes, brings the stack up on a
fresh database, discards a warm-up trial, sweeps, renders figures, and tears down.
Output lands in `results/<UTC timestamp>_<config>/`, overlays in `results/combined/`,
progress in `results/sweep_run.log`. A PID lockfile stops two sweeps colliding.

Sweep knobs are constants at the top of `attacker.py` (`TRIALS`, `DELAYS`); credentials
come from `PORTAL_USERNAME` / `PORTAL_PASSWORD`. `--trials` and `--delays` override them
for a quick shakedown.

## Figures

`figures.py` takes one or more `Label=path/results.csv` plus `--out=DIR`, and is run
automatically by the sweep. Per config it writes the step timeline, the outcome scatter,
and four tables; with several inputs it also writes a combined measurement table.
All statistics are means. Tables are tab-delimited `.txt` for Word's
Insert > Table > Convert Text to Table.

## Reading the output

`results.csv` is one row per trial, 66 columns: 20 stages x (`_start`, `_end`, `_ms`),
plus `attacker_start_time`, `blob_read_time`, `attacker_modify_time`,
`attacker_modify_done`, `attacker_delay`, `outcome`.

| outcome | meaning |
|---|---|
| `leak` | reply contained a seeded credential |
| `blocked` | scanner rejected the content before the agent ran |
| `rejected` | integrity check caught the swap |
| `safe` | poisoned bytes may have reached the model, which did not comply |
| `error` | trial raised |

The window runs from `T_check` (`blob_read_time`, the instant the blob service opens the
file for the webapp's scan fetch) to `T_use` (`Agent_retrieves_document_end`, the bytes in
the agent's hands). A trial is in-window when `attacker_modify_done` falls between them,
tested per trial rather than against the medians.

`table_success_by_delay` splits success into `P(hit)`, whether the swap landed in the
window, and `P(comply | hit)`, whether the model then acted on the injection. The configs
differ in which of the two they defeat.

## Layout

```
<config>/               BaseLine | Tight | Secure, one full stack each
  docker-compose.yml    5 services: db, cloud, security-check, mcp-server, webapp
  db/init/              schema and seed data, run once on a fresh volume
  MCP Server/           FastMCP server and LLM tool loop
  WebApp/               FastAPI: upload, workflow, chat, portal
  Cloud/                blob store, the object the attacker overwrites
  SecurityCheck/        stateless content scanner
run_sweep.sh / .ps1     full sweep of all three, then figures
sweep_all.py            the orchestration both wrappers call
attacker.py             sweep driver and log collector -> results.csv
figures.py              results.csv -> figures and tables
Old/results/            superseded runs, not comparable
```

Portal at `http://localhost:8010`, sign in `analyst` / `analyst-password`. It writes to
the same database the sweep reads, so do not use it mid-sweep.
