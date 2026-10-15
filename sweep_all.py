import argparse
import os
import pathlib
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

import httpx

ROOT = pathlib.Path(__file__).resolve().parent
RESULTS = ROOT / "results"
PIDFILE = RESULTS / ".sweep.pid"
LOG = RESULTS / "sweep_run.log"
CONFIGS = ["BaseLine", "Tight", "Secure"]

PORTS_REQUIRED = {8010: "webapp", 9000: "blob"}
PORTS_OPTIONAL = {9001: "scanner", 3000: "mcp", 5432: "db"}
MODEL = os.environ.get("OLLAMA_MODEL", "qwen3:latest")


def _ollama_url():
    h = os.environ.get("OLLAMA_HOST", "").strip()
    if not h:
        return "http://127.0.0.1:11434"
    if "://" not in h:
        host, _, port = h.partition(":")
        if host in ("", "0.0.0.0", "::", "[::]"):
            host = "127.0.0.1"
        h = f"http://{host}:{port or '11434'}"
    return h.rstrip("/")


OLLAMA = _ollama_url()

sys.path.insert(0, str(ROOT))
import attacker


def log(msg):
    line = f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def die(msg):
    log(f"PREFLIGHT FAILED: {msg}")
    raise SystemExit(2)


def preflight(configs):
    for cfg in configs:
        if not (ROOT / cfg / "docker-compose.yml").is_file():
            die(f"{cfg}/docker-compose.yml not found (run from the repo root)")

    import importlib.util
    missing = [m for m in ("httpx", "matplotlib")
               if importlib.util.find_spec(m) is None]
    if missing:
        die("missing host dependency: " + ", ".join(missing)
            + ". pip install httpx matplotlib")

    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        die("docker is not responding; is Docker Desktop running?")

    def listening(port):
        with socket.socket() as sk:
            sk.settimeout(0.4)
            return sk.connect_ex(("127.0.0.1", port)) == 0

    busy = [f"{p} ({n})" for p, n in PORTS_REQUIRED.items() if listening(p)]
    if busy:
        die("host ports already in use: " + ", ".join(busy)
            + ". Another config is probably still up; run "
              "`docker compose down` in each of BaseLine/Tight/Secure.")
    noted = [f"{p} ({n})" for p, n in PORTS_OPTIONAL.items() if listening(p)]
    if noted:
        log("note: something already listens on " + ", ".join(noted)
            + " -- harmless, the stack reaches these over the compose network")

    try:
        tags = httpx.get(f"{OLLAMA}/api/tags", timeout=5.0).json()
    except Exception as e:
        die(f"ollama unreachable at {OLLAMA} ({e}). Start it with `ollama serve`.")
    names = {m["name"] for m in tags.get("models", [])}
    if MODEL not in names:
        die(f"ollama model {MODEL!r} not pulled. Run: ollama pull {MODEL}")

    log(f"preflight ok: docker up, ports free, ollama has {MODEL}")


def pid_alive(pid):
    if os.name == "nt":
        out = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             f"if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{'yes'}}"],
            capture_output=True, text=True).stdout
        return "yes" in out
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError) as e:
        return isinstance(e, PermissionError)


def claim_lock():
    RESULTS.mkdir(parents=True, exist_ok=True)
    if PIDFILE.exists():
        try:
            other = int(PIDFILE.read_text().strip())
        except ValueError:
            other = None
        if other and other != os.getpid() and pid_alive(other):
            log(f"REFUSING TO START: sweep already running as PID {other}")
            raise SystemExit(1)
        log("clearing stale pidfile")
    PIDFILE.write_text(str(os.getpid()), encoding="utf-8")


def compose(cfg, *args):
    return subprocess.run(["docker", "compose", *args], cwd=str(ROOT / cfg),
                          capture_output=True, text=True)


def sweep(cfg):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = RESULTS / f"{stamp}_{cfg.lower()}"
    out.mkdir(parents=True, exist_ok=True)

    attacker.rows.clear()
    attacker.rates.clear()
    attacker._containers = None

    log(f"{cfg}: starting fresh (wiping volumes)")
    compose(cfg, "down", "-v")
    compose(cfg, "up", "-d", "--force-recreate")
    time.sleep(20)
    log(f"{cfg}: " + compose(cfg, "ps", "--format", "{{.Service}} {{.Status}}")
        .stdout.replace("\n", " | ").strip())

    attacker.login()
    attacker.warm()
    attacker.trial(100)
    attacker.rows.clear()

    log(f"{cfg}: sweeping {len(attacker.DELAYS)} delays x {attacker.TRIALS} trials "
        f"= {len(attacker.DELAYS) * attacker.TRIALS} runs")
    t0 = time.perf_counter()
    for d in attacker.DELAYS:
        leaks = sum(attacker.trial(d)["outcome"] == "leak"
                    for _ in range(attacker.TRIALS))
        log(f"{cfg}: {d:>3} ms  leak {leaks}/{attacker.TRIALS} "
            f"= {leaks/attacker.TRIALS:.0%}")

    attacker.write_results(out)
    log(f"{cfg}: {len(attacker.rows)} trials in {(time.perf_counter()-t0)/60:.1f} min -> {out}")

    r = subprocess.run([sys.executable, "figures.py",
                        f"{cfg}={out / 'results.csv'}", f"--out={out}"],
                       cwd=str(ROOT), capture_output=True, text=True)
    log(f"{cfg}: figures rc={r.returncode} {r.stdout.strip()}{r.stderr.strip()[:300]}")
    compose(cfg, "down")
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Full attacker.py sweep of every configuration, then figures.")
    ap.add_argument("--configs", nargs="+", default=CONFIGS, choices=CONFIGS,
                    help="configurations to sweep (default: all three)")
    ap.add_argument("--skip-preflight", action="store_true",
                    help="skip the dependency and port checks")
    ap.add_argument("--trials", type=int, metavar="N",
                    help="override attacker.TRIALS (default: whatever "
                         "attacker.py declares). Useful for a quick shakedown.")
    ap.add_argument("--delays", metavar="MS",
                    help="override attacker.DELAYS with a comma-separated list, "
                         "e.g. --delays 5,20,400")
    ap.add_argument("--dry-run", action="store_true",
                    help="run preflight, print the plan, and exit without "
                         "touching docker or running a single trial")
    args = ap.parse_args()

    if args.trials is not None:
        if args.trials < 1:
            ap.error("--trials must be at least 1")
        attacker.TRIALS = args.trials
    if args.delays is not None:
        try:
            attacker.DELAYS = [int(x) for x in args.delays.split(",") if x.strip()]
        except ValueError:
            ap.error("--delays must be a comma-separated list of integers")
        if not attacker.DELAYS:
            ap.error("--delays produced an empty list")
    if args.trials is not None or args.delays is not None:
        log(f"OVERRIDE: {len(attacker.DELAYS)} delays x {attacker.TRIALS} trials "
            f"= {len(attacker.DELAYS) * attacker.TRIALS} runs per config "
            f"(not a publishable sweep)")

    if args.dry_run:
        if not args.skip_preflight:
            preflight(args.configs)
        per = len(attacker.DELAYS) * attacker.TRIALS
        log("DRY RUN -- nothing was started. Plan was:")
        log(f"  configs : {', '.join(args.configs)}")
        log(f"  sweep   : {len(attacker.DELAYS)} delays x {attacker.TRIALS} "
            f"trials = {per} trials per config, {per * len(args.configs)} total")
        log(f"  delays  : {attacker.DELAYS}")
        log(f"  output  : {RESULTS}{os.sep}<UTC timestamp>_<config>{os.sep}")
        log(f"  figures : per config, plus "
            f"{'combined/' if len(args.configs) > 1 else 'no combined (single config)'}")
        return

    claim_lock()
    try:
        if not args.skip_preflight:
            preflight(args.configs)

        for cfg in args.configs:
            compose(cfg, "down")

        dirs = {cfg: sweep(cfg) for cfg in args.configs}

        specs = [f"{cfg}={d / 'results.csv'}" for cfg, d in dirs.items()
                 if (d / "results.csv").exists()]
        if len(specs) > 1:
            combined = RESULTS / "combined"
            combined.mkdir(parents=True, exist_ok=True)
            r = subprocess.run([sys.executable, "figures.py", *specs,
                                f"--out={combined}"],
                               cwd=str(ROOT), capture_output=True, text=True)
            log(f"combined figures rc={r.returncode} {r.stdout.strip()}{r.stderr.strip()[:300]}")
        log("ALL DONE")
    finally:
        if PIDFILE.exists() and PIDFILE.read_text().strip() == str(os.getpid()):
            PIDFILE.unlink()


if __name__ == "__main__":
    main()
