#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PY=""
for c in python3 python py; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
[ -n "$PY" ] || { echo "no python interpreter on PATH" >&2; exit 2; }

DETACHED=0
DRYRUN=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --detached) DETACHED=1 ;;
    --dry-run)  DRYRUN=1; ARGS+=("$a") ;;
    *)          ARGS+=("$a") ;;
  esac
done

if [ "$DETACHED" -eq 1 ] && [ "$DRYRUN" -eq 1 ]; then
  echo "--dry-run and --detached are mutually exclusive" >&2
  exit 2
fi

mkdir -p results
if [ "$DETACHED" -eq 1 ]; then
  nohup "$PY" sweep_all.py "${ARGS[@]+"${ARGS[@]}"}" \
    >results/sweep_stdout.log 2>results/sweep_stderr.log &
  echo "sweep detached as PID $!"
  echo "  progress : tail -f results/sweep_run.log"
  echo "  stop     : kill $!"
else
  exec "$PY" sweep_all.py "${ARGS[@]+"${ARGS[@]}"}"
fi
