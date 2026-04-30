import contextlib
import csv
import io
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

import attacker

# --- run configuration ---

MARKER = "sk-acme-fake-abc123xyz"
TOL_MS = 10
MAX_EXPAND_MS = 30_000
PACE = 5
REPEAT = 3

SEED_DELAYS_MS = (10, 25, 50, 75, 100, 250, 500, 1000, 2000, 4000, 8000)

CONTAINERS = ["cloud-blob", "webapp", "mcp-testdb-server"]

OUT_DIR = Path(__file__).resolve().parent
# Each run gets its own folder: SWEEP_RUNS_ROOT/<run_id>/
# containing run.csv plus four PNGs (no files written beside the script).
SWEEP_RUNS_ROOT = OUT_DIR / "sweep_runs"
RUN_ARTIFACT_NAMES = (
    "run.csv",
    "sweep_scatter.png",
    "sweep_probe_table.png",
    "sweep_latency_ranges.png",
)

# Each tuple: (label for PNG table, gap key, start event, end event)
PIPELINE_STEPS = [
    ("DB write (mark safe)", "db_write", "security_check_done", "marked_safe_in_db"),
    ("SSE handshake", "sse_handshake", "mcp_sse_connect_start", "mcp_sse_connected"),
    ("LLM inference (1st round)", "llm_round0", "llm_workflow_start", "llm_round_done"),
    ("MCP content re-fetch", "mcp_read_document", "read_document_plain_start", "mcp_content_read"),
    ("Total TOCTOU gap", "total_toctou_gap", "blob_fetched_for_security_check", "mcp_content_read"),
]

GAP_KEYS = [k for _a, k, _b, _c in PIPELINE_STEPS]

probes = []
probe_details = []
CURRENT_RUN_ID: str | None = None


# --- CSV logging (one run.csv per run folder) ---


def _gap_range_for_csv(gaps: dict, key: str) -> str:
    vals = gaps.get(key, [])
    if not vals:
        return ""
    return f"{int(min(vals))}-{int(max(vals))}"


def _run_csv_fieldnames() -> list[str]:
    return (
        ["record_type"]
        + [
            "run_id",
            "started_utc",
            "finished_utc",
            "lo_edge_ms",
            "hi_edge_ms",
            "window_ms",
            "no_seed",
            "n_probes",
            "pace_s",
            "repeat",
        ]
        + [f"gap_{k}" for k in GAP_KEYS]
        + [
            "delay_ms",
            "http_code",
            "outcome",
            "leaked",
            "duration_s",
            "doc_id",
            "error",
        ]
    )


def _empty_probe_cells() -> dict:
    return {
        "delay_ms": "",
        "http_code": "",
        "outcome": "",
        "leaked": "",
        "duration_s": "",
        "doc_id": "",
        "error": "",
    }


def _empty_summary_cells() -> dict:
    return {
        "started_utc": "",
        "finished_utc": "",
        "lo_edge_ms": "",
        "hi_edge_ms": "",
        "window_ms": "",
        "no_seed": "",
        "n_probes": "",
        "pace_s": "",
        "repeat": "",
        **{f"gap_{k}": "" for k in GAP_KEYS},
    }



def write_run_csv(
    run_dir: Path,
    run_id: str,
    started: datetime,
    finished: datetime,
    lo_edge: int,
    hi_edge: int,
    no_seed: bool,
    gaps: dict,
    n_probes: int,
) -> Path:
    """Single CSV per run: one `summary` row then one `probe` row per probe."""
    window = hi_edge - lo_edge if not no_seed else ""
    path = run_dir / RUN_ARTIFACT_NAMES[0]
    fields = _run_csv_fieldnames()

    summary = {
        "record_type": "summary",
        "run_id": run_id,
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat(),
        "lo_edge_ms": "" if no_seed else lo_edge,
        "hi_edge_ms": "" if no_seed else hi_edge,
        "window_ms": window,
        "no_seed": str(no_seed).lower(),
        "n_probes": n_probes,
        "pace_s": PACE,
        "repeat": REPEAT,
        **_empty_probe_cells(),
    }
    for k in GAP_KEYS:
        summary[f"gap_{k}"] = _gap_range_for_csv(gaps, k)

    rows: list[dict] = [summary]
    for d in probe_details:
        if d.get("run_id") != run_id:
            continue
        err = d.get("error") or ""
        code = d.get("code")
        leaked = d.get("leaked", False)
        kind = classify(code, leaked) if not err else "error"
        rows.append(
            {
                "record_type": "probe",
                "run_id": run_id,
                **_empty_summary_cells(),
                "delay_ms": d.get("delay_ms", ""),
                "http_code": code if code is not None else "",
                "outcome": kind,
                "leaked": str(bool(leaked)).lower(),
                "duration_s": d.get("duration_s", ""),
                "doc_id": d.get("doc_id", ""),
                "error": err,
            }
        )

    run_dir.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    return path


# --- docker log collection ---


def _docker_logs_since(container: str, since: str) -> str:
    try:
        r = subprocess.run(
            ["docker", "logs", "--since", since, container],
            capture_output=True,
            text=True,
            timeout=10,
            encoding="utf-8",
            errors="replace",
        )
        return r.stdout + r.stderr
    except Exception as e:
        return f"(error fetching logs: {e})"


def _parse_events(raw_logs: str, doc_id: int) -> list:
    events = []
    pattern = re.compile(
        r"\[(\w+)\s+([\d:.]+)\]\s+doc=(\d+)\s+event=(\S+)(.*)"
    )
    for line in raw_logs.splitlines():
        m = pattern.search(line)
        if not m:
            continue
        tag, ts, did, event, extra = m.groups()
        if int(did) != doc_id:
            continue
        events.append({"tag": tag, "time": ts, "event": event, "extra": extra.strip()})
    return events


def _collect_timeline(since_ts: str, doc_id: int) -> tuple[list, dict]:
    time.sleep(0.5)
    all_logs = {}
    all_events = []
    for cname in CONTAINERS:
        raw = _docker_logs_since(cname, since_ts)
        all_logs[cname] = raw
        parsed = _parse_events(raw, doc_id)
        all_events.extend(parsed)
    all_events.sort(key=lambda e: e["time"])
    return all_events, all_logs


# --- one HTTP / workflow probe ---


def probe_once(ms: int) -> dict:
    since_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    time.sleep(0.3)

    attacker.DELAY_MS = ms
    t0 = time.perf_counter()

    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code, body = attacker.run_case("/api/upload/vulnerable", quiet=True)
    except Exception as e:
        duration_s = time.perf_counter() - t0
        return {
            "delay_ms": ms,
            "code": None,
            "leaked": False,
            "error": str(e),
            "duration_s": duration_s,
            "timeline": [],
            "logs": {},
            "run_id": CURRENT_RUN_ID,
        }

    leaked = MARKER in body
    duration_s = time.perf_counter() - t0
    probes.append((ms, code, leaked))

    doc_id = attacker._last_doc_id
    all_events, all_logs = _collect_timeline(since_ts, doc_id)

    detail = {
        "delay_ms": ms,
        "code": code,
        "leaked": leaked,
        "duration_s": round(duration_s, 3),
        "doc_id": doc_id,
        "timeline": all_events,
        "logs": all_logs,
        "run_id": CURRENT_RUN_ID,
    }
    probe_details.append(detail)
    return detail


def probe(ms: int) -> bool:
    detail = probe_once(ms)
    leaked = detail["leaked"]

    if detail.get("error"):
        print(f"{ms} ms  error")
    else:
        if leaked:
            print(f"{ms} ms  leak")
        else:
            print(f"{ms} ms  no leak")

    if PACE:
        time.sleep(PACE)

    return leaked


# --- binary search on delay (ms) ---


def bisect_low(lo: int, hi: int) -> int:
    while hi - lo > TOL_MS:
        mid = (lo + hi) // 2
        leaked = probe(mid)
        if leaked:
            hi = mid
        else:
            lo = mid
    return hi


def bisect_high(lo: int, hi: int) -> int:
    while hi - lo > TOL_MS:
        mid = (lo + hi) // 2
        leaked = probe(mid)
        if leaked:
            lo = mid
        else:
            hi = mid
    return lo


# --- outcome labels for plot ---


def classify(code, leaked: bool) -> str:
    if leaked:
        return "leak"
    if code == 403:
        return "blocked"
    return "safe"


def _http_cell(code) -> str:
    if code is None:
        return "err"
    return str(code)


def _outcome_cell(kind: str) -> str:
    if kind == "leak":
        return "LEAK"
    if kind == "blocked":
        return "blocked"
    return "safe"


# --- timing gaps from MCP / webapp logs (leaked probes only) ---


def _seconds_of_day(ts: str) -> float:
    parts = ts.split(":")
    h = int(parts[0])
    m = int(parts[1])
    s = float(parts[2])
    return h * 3600 + m * 60 + s


def _gap_ms_first_pair(events_sorted: list, start_event: str, end_event: str):
    start_idx = None
    for i, ev in enumerate(events_sorted):
        if ev["event"] == start_event:
            start_idx = i
            break
    if start_idx is None:
        return None
    t0 = _seconds_of_day(events_sorted[start_idx]["time"])
    for j in range(start_idx + 1, len(events_sorted)):
        ev = events_sorted[j]
        if ev["event"] != end_event:
            continue
        t1 = _seconds_of_day(ev["time"])
        return round((t1 - t0) * 1000, 1)
    return None


def gather_gap_stats(probe_details_list: list) -> dict:
    gaps = {}

    for detail in probe_details_list:
        if not detail["leaked"]:
            continue
        timeline = detail["timeline"]
        if not timeline:
            continue

        for _label, key, start_ev, end_ev in PIPELINE_STEPS:
            ms = _gap_ms_first_pair(timeline, start_ev, end_ev)
            if ms is None:
                continue
            if key not in gaps:
                gaps[key] = []
            gaps[key].append(ms)

    return gaps


def _format_range(vals: list) -> str:
    if not vals:
        return "—"
    mn = min(vals)
    mx = max(vals)
    return f"{int(mn)}–{int(mx)} ms"


def build_range_table_rows(gaps: dict) -> list:
    rows = []
    for display_name, key, _a, _b in PIPELINE_STEPS:
        vals = gaps.get(key, [])
        row = [display_name, _format_range(vals)]
        rows.append(row)
    return rows


# --- matplotlib ---



def _style_header_row(table, num_columns: int):
    for col in range(num_columns):
        cell = table[(0, col)]
        cell.set_facecolor("#333")
        cell.set_text_props(color="white", weight="bold")


def _scatter_figure(data, lo_edge: int, hi_edge: int, no_seed: bool):
    colors = {
        "blocked": "#7f7f7f",
        "leak": "#d62728",
        "safe": "#2ca02c",
    }
    markers = {
        "blocked": "X",
        "leak": "*",
        "safe": "o",
    }
    legend_labels = {
        "blocked": "blocked (403)",
        "leak": "LEAK (exfil)",
        "safe": "safe (no exfil)",
    }

    fig, ax = plt.subplots(figsize=(11, 6.5))
    if not data:
        ax.text(0.5, 0.5, "no probes recorded", ha="center", va="center", transform=ax.transAxes)
        ax.set_axis_off()
        return fig

    if not no_seed:
        width_ms = hi_edge - lo_edge
        label = f"vulnerable window  {lo_edge}-{hi_edge} ms  ({width_ms} ms wide)"
        ax.axvspan(lo_edge, hi_edge, color="#d62728", alpha=0.12, label=label)
        ax.axvline(lo_edge, color="#d62728", linestyle="--", alpha=0.7)
        ax.axvline(hi_edge, color="#d62728", linestyle="--", alpha=0.7)

    for kind in ("blocked", "leak", "safe"):
        xs = [d for d, code, leaked in data if classify(code, leaked) == kind]
        ys = [1] * len(xs)
        ax.scatter(
            xs,
            ys,
            c=colors[kind],
            marker=markers[kind],
            s=180,
            label=legend_labels[kind],
            edgecolors="black",
            linewidths=0.6,
            zorder=3,
        )

    ax.set_yticks([])
    ax.set_xlabel("Attacker delay (ms) before malicious blob PUT  [symlog]")
    ax.set_xscale("symlog", linthresh=10)
    max_delay = max(r[0] for r in data)
    ax.set_xlim(-2, max(max_delay * 1.3, 10))

    title = "TOCTOU delay sweep — /api/upload/vulnerable"
    if no_seed:
        title += "\n(no leak in seed hunt — window not computed)"
    ax.set_title(title)
    ax.legend(loc="upper right", framealpha=0.95)
    ax.grid(True, axis="x", which="both", alpha=0.3)

    fig.text(
        0.5,
        0.02,
        "Attacker model: after POST /api/workflow starts the pipeline, the client waits delay ms, "
        "then PUTs malicious CSV to the blob URL (same object the security/MCP paths read). "
        "Each point is one probe at that delay.",
        ha="center",
        fontsize=9,
    )
    fig.subplots_adjust(bottom=0.18)
    return fig



def _probe_table_figure(probe_rows: list, data):
    fig, ax = plt.subplots(figsize=(11, max(4.0, 0.32 * max(len(probe_rows), 3))))
    ax.axis("off")
    tbl = ax.table(
        cellText=probe_rows,
        colLabels=["delay", "http", "outcome"],
        cellLoc="center",
        loc="center",
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(10)
    tbl.scale(0.6, 1.35)
    face = {"blocked": "#eeeeee", "leak": "#ffd6d6", "safe": "#d6f5d6"}
    if data:
        row_index = 1
        for delay_ms, code, leaked in data:
            kind = classify(code, leaked)
            tbl[(row_index, 2)].set_facecolor(face[kind])
            row_index += 1
    _style_header_row(tbl, 3)
    fig.tight_layout()
    return fig


def _range_table_figure(gaps: dict):
    fig, ax = plt.subplots(figsize=(10, 4.5))
    ax.axis("off")
    range_rows = build_range_table_rows(gaps)
    tbl = ax.table(
        cellText=range_rows,
        colLabels=["step (leaked probes)", "latency range"],
        cellLoc="left",
        loc="center",
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(10)
    tbl.scale(0.65, 1.45)
    _style_header_row(tbl, 2)
    fig.tight_layout()
    return fig


def save_all_sweep_pngs(
    run_dir: Path, lo_edge: int, hi_edge: int, gaps: dict, *, no_seed: bool = False
) -> list[Path]:
    data = sorted(probes, key=lambda r: r[0])
    paths: list[Path] = []
    run_dir.mkdir(parents=True, exist_ok=True)

    _, *png_names = RUN_ARTIFACT_NAMES
    png_scatter, png_probe_table, png_latency_ranges = (run_dir / n for n in png_names)

    fig1 = _scatter_figure(data, lo_edge, hi_edge, no_seed)
    fig1.savefig(str(png_scatter), dpi=130, bbox_inches="tight")
    plt.close(fig1)
    paths.append(png_scatter)

    probe_rows = _build_probe_table_rows(data)
    fig2 = _probe_table_figure(probe_rows, data)
    fig2.savefig(str(png_probe_table), dpi=130, bbox_inches="tight")
    plt.close(fig2)
    paths.append(png_probe_table)

    fig3 = _range_table_figure(gaps)
    fig3.savefig(str(png_latency_ranges), dpi=130, bbox_inches="tight")
    plt.close(fig3)
    paths.append(png_latency_ranges)

    return paths


def _build_probe_table_rows(data) -> list:
    if not data:
        return [["—", "—", "—"]]
    rows = []
    for delay_ms, code, leaked in data:
        kind = classify(code, leaked)
        rows.append(
            [
                f"{delay_ms} ms",
                _http_cell(code),
                _outcome_cell(kind),
            ]
        )
    return rows


# --- main sweep phases ---


def find_first_leaking_seed() -> int | None:
    for delay_ms in SEED_DELAYS_MS:
        leaked = probe(delay_ms)
        if leaked:
            return delay_ms
    return None


def find_lower_edge(seed: int) -> int:
    leaked_at_zero = probe(0)
    if leaked_at_zero:
        return 0
    return bisect_low(0, seed)


def find_upper_edge(seed: int) -> int:
    hi = seed
    while hi * 2 <= MAX_EXPAND_MS:
        hi = hi * 2
        leaked = probe(hi)
        if not leaked:
            return bisect_high(seed, hi)
    return hi


def repeat_probes_at_test_points(lo_edge: int, seed: int, hi_edge: int):
    mid_lo = (lo_edge + seed) // 2
    mid_hi = (seed + hi_edge) // 2
    test_points = sorted(set([0, lo_edge, seed, hi_edge, mid_lo, mid_hi]))
    for delay_ms in test_points:
        for _ in range(REPEAT):
            probe(delay_ms)


def main():
    global probes, probe_details, CURRENT_RUN_ID

    started = datetime.now(timezone.utc)
    run_id = started.strftime("%Y%m%d_%H%M%S")
    run_dir = SWEEP_RUNS_ROOT / run_id
    run_dir.mkdir(parents=True, exist_ok=True)


    CURRENT_RUN_ID = run_id
    probes = []
    probe_details = []

    seed = find_first_leaking_seed()
    if seed is None:
        gaps = gather_gap_stats(probe_details)
        paths = save_all_sweep_pngs(run_dir, 0, 0, gaps, no_seed=True)
        finished = datetime.now(timezone.utc)
        write_run_csv(
            run_dir,
            run_id,
            started,
            finished,
            0,
            0,
            True,
            gaps,
            len(probe_details),
        )
        CURRENT_RUN_ID = None
        return

    lo_edge = find_lower_edge(seed)
    hi_edge = find_upper_edge(seed)
    repeat_probes_at_test_points(lo_edge, seed, hi_edge)

    gaps = gather_gap_stats(probe_details)
    paths = save_all_sweep_pngs(run_dir, lo_edge, hi_edge, gaps, no_seed=False)
    finished = datetime.now(timezone.utc)
    write_run_csv(
        run_dir,
        run_id,
        started,
        finished,
        lo_edge,
        hi_edge,
        False,
        gaps,
        len(probe_details),
    )
    CURRENT_RUN_ID = None


if __name__ == "__main__":
    main()
