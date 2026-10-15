"""Temporary dense sweep: every attacker delay from 1 to 500 ms, 5 trials each.

2500 runs per config, the same budget as the standard sweep (25 delays x 100 trials),
spread over every millisecond so the window edges are resolved to 1 ms. figures_temp.py
bins the results (10 ms bins = 50 trials) for per-range rates.

Per config: wipe volumes, rebuild images, bring the stack up, discard a warm-up trial,
sweep, write results.csv, render figures_temp.py, tear down. Images are always rebuilt:
compose names images after the project, so a stale image would otherwise run old code.
Output goes to results/dense_1-500ms/ so the existing results are not touched.

Usage:
  python attacker_temp.py                          # BaseLine, Tight, Tight-both, Secure
  python attacker_temp.py --configs Tight Secure   # a subset
  python attacker_temp.py --dry-run                # preflight + plan only
"""
import argparse
import subprocess
import sys
import time
from datetime import datetime, timezone

import attacker
import sweep_all
from sweep_all import ROOT, log

attacker.DELAYS = list(range(1, 501))
attacker.TRIALS = 5

OUT = ROOT / "results" / "dense_1-500ms"

# label -> folder holding its docker-compose.yml
CONFIGS = {
    "BaseLine": "BaseLine",
    "Tight": "Tight",
    "Tight-both": "Old/tight-both",
    "Secure": "Secure",
}


def compose(folder, *args):
    return subprocess.run(["docker", "compose", *args], cwd=str(ROOT / folder),
                          capture_output=True, text=True)


def sweep(label, folder):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = OUT / f"{stamp}_{label.lower()}"
    out.mkdir(parents=True, exist_ok=True)

    attacker.rows.clear()
    attacker.rates.clear()
    attacker._containers = None

    log(f"{label}: starting fresh (wiping volumes, rebuilding images)")
    compose(folder, "down", "-v")
    r = compose(folder, "up", "-d", "--build", "--force-recreate")
    if r.returncode != 0:
        log(f"{label}: compose up FAILED rc={r.returncode} {r.stderr.strip()[-500:]}")
        return None
    time.sleep(20)
    log(f"{label}: " + compose(folder, "ps", "--format", "{{.Service}} {{.Status}}")
        .stdout.replace("\n", " | ").strip())

    attacker.login()
    attacker.warm()
    attacker.trial(100)
    attacker.rows.clear()

    log(f"{label}: sweeping {len(attacker.DELAYS)} delays x {attacker.TRIALS} trials "
        f"= {len(attacker.DELAYS) * attacker.TRIALS} runs")
    t0 = time.perf_counter()
    leaks = followed = 0
    for i, d in enumerate(attacker.DELAYS, 1):
        for _ in range(attacker.TRIALS):
            row = attacker.trial(d)
            leaks += row["outcome"] == "leak"
            followed += bool(row.get("Agent_prohibited_tool_call_start"))
        if i % 10 == 0:
            n = i * attacker.TRIALS
            log(f"{label}: through {d:>3} ms  followed {followed}/{n}  leak {leaks}/{n}  "
                f"({(time.perf_counter()-t0)/60:.1f} min)")
            # checkpoint so a killed run still leaves usable data
            attacker.write_results(out)

    attacker.write_results(out)
    log(f"{label}: {len(attacker.rows)} trials in {(time.perf_counter()-t0)/60:.1f} min -> {out}")

    r = subprocess.run([sys.executable, "figures_temp.py",
                        f"{label}={out / 'results.csv'}", f"--out={out}"],
                       cwd=str(ROOT), capture_output=True, text=True)
    log(f"{label}: figures rc={r.returncode} {r.stderr.strip()[-300:]}")
    compose(folder, "down")
    return out


def main():
    ap = argparse.ArgumentParser(description="Dense 1-500 ms sweep of each configuration.")
    ap.add_argument("--configs", nargs="+", default=list(CONFIGS), choices=list(CONFIGS))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    folders = [CONFIGS[c] for c in args.configs]

    if args.dry_run:
        sweep_all.preflight(folders)
        per = len(attacker.DELAYS) * attacker.TRIALS
        log("DRY RUN -- nothing was started. Plan was:")
        log(f"  configs : {', '.join(f'{c} ({CONFIGS[c]})' for c in args.configs)}")
        log(f"  sweep   : {attacker.DELAYS[0]}-{attacker.DELAYS[-1]} ms, {len(attacker.DELAYS)} delays "
            f"x {attacker.TRIALS} trials = {per} per config, {per * len(args.configs)} total")
        log(f"  output  : {OUT}")
        return

    sweep_all.claim_lock()
    try:
        sweep_all.preflight(folders)
        for f in CONFIGS.values():
            compose(f, "down")

        dirs = {}
        for label in args.configs:
            out = sweep(label, CONFIGS[label])
            if out and (out / "results.csv").exists():
                dirs[label] = out

        if len(dirs) > 1:
            combined = OUT / "combined"
            combined.mkdir(parents=True, exist_ok=True)
            r = subprocess.run([sys.executable, "figures_temp.py",
                                *[f"{c}={d / 'results.csv'}" for c, d in dirs.items()],
                                f"--out={combined}"],
                               cwd=str(ROOT), capture_output=True, text=True)
            log(f"combined figures rc={r.returncode} {r.stderr.strip()[-300:]}")
        log("ALL DONE")
    finally:
        if sweep_all.PIDFILE.exists():
            sweep_all.PIDFILE.unlink()


if __name__ == "__main__":
    main()
