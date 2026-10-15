import csv
import random
import re
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FixedLocator, FuncFormatter

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_SOFT = "#52514e"
INK_MUTED = "#8a8981"
GRID = "#dcdbd4"

OUTCOME_STYLE = {
    "blocked": ("#2a78d6", "s", "Blocked at validation"),
    "leak": ("#eb6834", "o", "Exploited"),
    "rejected": ("#4a3aa7", "D", "Rejected by integrity check"),
    "safe": ("#1baf7a", "^", "Safe"),
}
RAMP = ["#e3edf9", "#cfe0f5", "#a9c8ec", "#7fabe0", "#5590d5", "#3d84cf", "#2a78d6", "#20609f", "#1c5197"]

MAIN, SUB = "main", "sub"

SEGMENTS_SPEC = [
    ("Workflow request",               "Document_lookup",                  MAIN, "2"),
    ("WebApp fetches bytes for scan (T_check)", "Blob_fetch",              MAIN, "3"),
    ("Content scan",                   "Initial_sec_validation",           MAIN, "5"),
    ("Verdict written to database",    "Document_marked_safe",             MAIN, "6"),
    ("Dispatch to the agent",          "Dispatch_to_agent",                MAIN, "7"),
    ("LLM inference",                  "LLM_inference",                    MAIN, "8"),
    ("Agent checks the SAFE flag",     "Agent_retrieves_document_state",   MAIN, "9"),
    ("Time of use read (T_use)",       "Agent_retrieves_document",         MAIN, "10"),
    ("Reasoning under injected context", "Agent_acts_on_document",         MAIN, "11"),
    ("Prohibited tool call",           "Agent_prohibited_tool_call",       MAIN, "12"),
]

START_SUBSTITUTE = {"Agent_acts_on_document": "Agent_retrieves_document_end"}


def _start_col(stage):
    return START_SUBSTITUTE.get(stage, f"{stage}_start")


SEGMENTS = [(label, _start_col(stage), f"{stage}_end")
            for label, stage, _k, _n in SEGMENTS_SPEC]
SEGMENT_KIND = {label: kind for label, _s, kind, _n in SEGMENTS_SPEC}
STEP_NUMBERS = {label: num for label, _s, _k, num in SEGMENTS_SPEC if num}


def step_label(name):
    n = STEP_NUMBERS.get(name)
    return f"{name} ({n})" if n else name


def to_seconds(ts):
    h, m, s = ts.split(":")
    return int(h) * 3600 + int(m) * 60 + float(s)


CHECK_REFS = ("Document_marked_safe_end", "Document_marked_safe_start", "Initial_sec_validation_end")


def delta_ms(row, a, b):
    x, y = row.get(a, ""), row.get(b, "")
    if not x or not y:
        return None
    d = (to_seconds(y) - to_seconds(x)) * 1000.0
    if d < -43200000.0:
        d += 86400000.0
    return round(d, 3)


def check_ref(row):
    for col in CHECK_REFS:
        if row.get(col):
            return col
    return None


def mean(vals):
    v = [x for x in vals if x is not None]
    return sum(v) / len(v) if v else None


def median(vals):
    v = sorted(vals)
    n = len(v)
    if not n:
        return None
    return v[n // 2] if n % 2 else (v[n // 2 - 1] + v[n // 2]) / 2


def quartiles(vals):
    v = sorted(vals)
    if not v:
        return None, None, None
    half = len(v) // 2
    return median(v[:half]) or v[0], median(v), median(v[half + (len(v) % 2):]) or v[-1]


def split_spec(spec):
    label, _, path = spec.rpartition("=")
    path = Path(path or spec)
    if not label:
        stem = path.parent.name
        label = stem.split("_", 2)[-1] if stem[:8].isdigit() else stem
    return label, path


def load(spec):
    label, path = split_spec(spec)
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    for r in rows:
        r["_delay"] = int(r["attacker_delay"]) if r["attacker_delay"] != "" else None
        ref = check_ref(r)
        r["_offset"] = delta_ms(r, "attacker_start_time", "attacker_modify_done")
        r["_t_scan"] = (delta_ms(r, "attacker_start_time", "blob_read_time")
                    if r.get("blob_read_time")
                    else delta_ms(r, "attacker_start_time", "Blob_fetch_start"))
        r["_t_check"] = delta_ms(r, "attacker_start_time", ref) if ref else None
        r["_t_use"] = delta_ms(r, "attacker_start_time", "Agent_retrieves_document_end")
        r["_window"] = delta_ms(r, ref, "Agent_retrieves_document_end") if ref else None
        for name, a, b in SEGMENTS:
            r[f"_seg::{name}"] = delta_ms(r, a, b)
    return {"label": label, "rows": rows}


def style_axes(ax, grid_axis="both"):
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=INK_SOFT, labelsize=8.5, length=3)
    if grid_axis in ("x", "y", "both"):
        ax.grid(axis=grid_axis, color=GRID, linewidth=0.7, alpha=0.7)
    ax.set_axisbelow(True)


def new_fig(w, h):
    fig, ax = plt.subplots(figsize=(w, h))
    fig.patch.set_facecolor(SURFACE)
    return fig, ax


def save(fig, out_dir, name):
    fig.savefig(out_dir / name, dpi=200, bbox_inches="tight", facecolor=SURFACE)
    plt.close(fig)
    print("wrote", name)


def measured_window(run):
    lo = mean([r["_t_scan"] for r in run["rows"] if r["_t_scan"] is not None])
    hi = mean([r["_t_use"] for r in run["rows"] if r["_t_use"] is not None])
    return lo, hi


def fig_outcome_by_offset(out_dir, runs):
    jitter = random.Random(11)
    fig, axes = plt.subplots(len(runs), 1, figsize=(7.2, 1.9 * len(runs)), sharex=True)
    fig.patch.set_facecolor(SURFACE)
    if len(runs) == 1:
        axes = [axes]

    for ax, run in zip(axes, runs):
        style_axes(ax, grid_axis="x")
        lo, hi = measured_window(run)
        for outcome, (color, marker, _label) in OUTCOME_STYLE.items():
            pts = [r for r in run["rows"] if r["outcome"] == outcome and r["_offset"] is not None]
            if not pts:
                continue
            ax.scatter([r["_offset"] for r in pts],
                       [jitter.uniform(0.18, 0.82) for _ in pts],
                       c=color, marker=marker, s=24, alpha=0.75,
                       edgecolors=SURFACE, linewidths=0.6)
        if lo is not None and hi is not None:
            ax.axvspan(lo, hi, color=OUTCOME_STYLE["leak"][0], alpha=0.10, linewidth=0)
            span = hi - lo
            for x, name in ((lo, "T_check"), (hi, "T_use")):
                ax.axvline(x, color=INK_SOFT, linestyle="--", linewidth=1.0)
                near_left = name == "T_check"
                ax.annotate(f"{name} = {x:.1f} ms", xy=(x, 0.0),
                            xycoords=("data", "axes fraction"),
                            xytext=(4 if near_left else -4, 5), textcoords="offset points",
                            ha="left" if near_left else "right", va="bottom",
                            fontsize=7.2, color=INK, clip_on=False,
                            bbox=dict(boxstyle="round,pad=0.22", fc=SURFACE, ec=GRID, lw=0.7))
            ax.text((lo + hi) / 2, 0.96, f"TOCTOU window  {span:.0f} ms",
                    fontsize=7.5, color=INK_SOFT, va="top", ha="center")
        ax.set_xscale("symlog", linthresh=1, linscale=0.45)
        ax.set_xlim(left=0)
        ax.set_ylim(0, 1)
        ax.set_yticks([])
        if len(runs) > 1:
            ax.set_ylabel(run["label"], fontsize=9, color=INK, rotation=90,
                          labelpad=8, va="center")

    span = max((r["_offset"] for run in runs for r in run["rows"]
                if r["_offset"] is not None), default=100.0)
    ticks = [t for t in (0, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000) if t <= span * 1.6]
    axes[-1].xaxis.set_major_locator(FixedLocator(ticks))
    axes[-1].xaxis.set_minor_locator(FixedLocator([]))
    axes[-1].xaxis.set_major_formatter(FuncFormatter(lambda v, _p: f"{v:g}"))
    axes[-1].set_xlabel("Time (ms)", fontsize=9, color=INK_SOFT)
    axes[0].legend(handles=[plt.Line2D([], [], color=c, marker=m, linestyle="", markersize=6, label=l)
                            for c, m, l in OUTCOME_STYLE.values()],
                   fontsize=8, ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.46), frameon=False)
    save(fig, out_dir, "fig_outcome_by_offset.png")


def fig_step_timeline(out_dir, runs):
    for run in runs:
        rows = run["rows"]

        def stamps(col):
            return [v for v in (delta_ms(r, "attacker_start_time", col) for r in rows) if v is not None]

        scan, use = measured_window(run)
        present = []
        for label, a, b in SEGMENTS:
            starts, ends = stamps(a), stamps(b)
            if starts and ends:
                present.append((mean(starts), label, a, b))
        present.sort(key=lambda x: x[0])
        segments = [(label, a, b) for _s, label, a, b in present]
        if not segments:
            continue

        log_scale = True

        def drawn_width(s0, e0):
            end = max(e0, s0 * 1.028 if s0 >= 1 else s0 + 0.4)
            if use is not None and e0 <= use:
                end = min(end, use)
            return max(end - s0, 0.0)

        fig, ax = new_fig(7.8, 0.5 * len(segments) + 1.6)
        style_axes(ax, grid_axis="x")

        right = 0.0
        for i, (label, a, b) in enumerate(segments):
            y = len(segments) - 1 - i
            starts, ends = stamps(a), stamps(b)
            s, e = mean(starts), mean(ends)
            q1, _m, q3 = quartiles(ends)
            if e <= 0:
                dur = e - s
                ax.annotate(f"{dur:.2f} ms  (before t=0)", xy=(0, y), xytext=(6, 0),
                            textcoords="offset points", va="center", ha="left",
                            fontsize=8, color=INK_MUTED)
                continue
            is_sub = SEGMENT_KIND.get(label) == SUB
            ax.barh(y, drawn_width(s, e), left=s, height=0.38 if is_sub else 0.55,
                    color=INK_MUTED if is_sub else RAMP[i % len(RAMP)],
                    alpha=0.55 if is_sub else 1.0,
                    edgecolor=SURFACE, linewidth=1.2, zorder=2)
            label_x = e
            if q1 is not None and q3 > q1:
                ax.plot([q1, q3], [y, y], color=INK, linewidth=1.0, zorder=3,
                        solid_capstyle="butt", alpha=0.55)
                label_x = max(label_x, q3)
            dur = e - s
            if dur < 1.0:
                fine = [r[f"_seg::{label}"] for r in rows if r.get(f"_seg::{label}") is not None]
                if fine:
                    dur = sum(fine) / len(fine)
            text = f"{dur:.2f} ms" if dur < 1.0 else f"{dur:.0f} ms"
            ax.annotate(text, xy=(label_x, y), xytext=(6, 0), textcoords="offset points",
                        va="center", ha="left", fontsize=8, color=INK)
            right = max(right, label_x)

        edge = right * (1.9 if log_scale else 1.16)
        if log_scale:
            ax.set_xscale("symlog", linthresh=1, linscale=0.45)
            ticks = [t for t in (0, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000) if t <= edge]
            ax.xaxis.set_major_locator(FixedLocator(ticks))
            ax.xaxis.set_minor_locator(FixedLocator([]))
            ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _p: f"{v:g}"))
        ax.set_xlim(0, edge)
        top = len(segments) - 0.15
        if scan is not None and use is not None:
            span = use - scan
            px = lambda v: ax.transData.transform((v, 0))[0]
            axis_px = px(edge) - px(0)
            narrow = (px(use) - px(scan)) < axis_px * 0.12
            ax.axvspan(scan, use, color=OUTCOME_STYLE["leak"][0], alpha=0.09, linewidth=0, zorder=0)
            for x in (scan, use):
                ax.axvline(x, color=INK_SOFT, linestyle="--", linewidth=1.0, zorder=1)
            if narrow:
                ax.annotate(f"check-to-use interval  {span:.0f} ms",
                            xy=(use, top), xytext=(use * 1.5 if log_scale else use + edge * 0.03, top),
                            ha="left", va="center", fontsize=8.5, color=INK,
                            arrowprops=dict(arrowstyle="-", color=INK, linewidth=0.8))
                ax.annotate(f"T_check = {scan:.1f} ms   T_use = {use:.1f} ms",
                            xy=(use, 0.0), xycoords=("data", "axes fraction"),
                            xytext=(6, 5), textcoords="offset points",
                            ha="left", va="bottom", fontsize=7.2, color=INK,
                            clip_on=False, zorder=5,
                            bbox=dict(boxstyle="round,pad=0.22", fc=SURFACE, ec=GRID, lw=0.7))
            else:
                ax.annotate("", xy=(use, top), xytext=(scan, top),
                            arrowprops=dict(arrowstyle="<|-|>", color=INK, linewidth=1.1))
                ax.text((scan + use) / 2, top + 0.16, f"check-to-use interval  {span:.0f} ms",
                        ha="center", fontsize=8.5, color=INK)
                for x, name in ((scan, "T_check"), (use, "T_use")):
                    at_left = x == scan
                    ax.annotate(f"{name} = {x:.1f} ms", xy=(x, 0.0),
                                xycoords=("data", "axes fraction"),
                                xytext=(4 if at_left else -4, 5), textcoords="offset points",
                                ha="left" if at_left else "right", va="bottom",
                                fontsize=7.2, color=INK, clip_on=False, zorder=5,
                                bbox=dict(boxstyle="round,pad=0.22", fc=SURFACE, ec=GRID, lw=0.7))

        anchor = None
        if scan is not None:
            for i, (_l, a, b) in enumerate(segments):
                s, e = mean(stamps(a)), mean(stamps(b))
                if s is not None and e is not None and s <= scan <= e:
                    anchor = i
                    break
        if scan is not None and anchor is not None:
            ay = len(segments) - 1 - anchor + 0.42
            ax.plot([scan], [ay], marker="v", markersize=4.5, color=INK, zorder=6, clip_on=False)
            ax.annotate("start of TOCTOU window", xy=(scan, ay), xytext=(8, 0), textcoords="offset points", va="center", ha="left",
                        fontsize=7, color=INK_SOFT, zorder=6)

        ax.set_yticks(range(len(segments)))
        ax.set_yticklabels([step_label(l) for l, _a, _b in reversed(segments)], fontsize=8.5)
        for tick, (l, _a, _b) in zip(ax.get_yticklabels(), reversed(segments)):
            if SEGMENT_KIND.get(l) == SUB:
                tick.set_color(INK_MUTED)
                tick.set_fontsize(7.6)
        ax.set_xlabel("Time (ms)", fontsize=9, color=INK_SOFT)
        ax.set_ylim(-0.6, top + 0.55)
        ax.set_title(f"Step Timeline - {run['label']}", fontsize=9.5, color=INK)
        suffix = "" if len(runs) == 1 else "_" + re.sub(r"[^A-Za-z0-9]+", "", run["label"]).lower()
        save(fig, out_dir, f"fig_step_timeline{suffix}.png")


ARROW_DURATIONS = [
    ("1",  "Benign upload (document row insert only)", "DB_upload_insert"),
    ("2",  "Workflow request",                         "Document_lookup"),
    ("3",  "WebApp fetches bytes for scan (T_check)",  "Blob_fetch"),
    ("4",  "Attacker overwrite",                       "_attacker"),
    ("5",  "Content scan",                             "Initial_sec_validation"),
    ("6",  "Verdict written to database",              "Document_marked_safe"),
    ("7",  "Dispatch to the agent",                    "Dispatch_to_agent"),
    ("8",  "LLM inference",                            "LLM_inference"),
    ("9",  "Agent checks the SAFE flag",               "Agent_retrieves_document_state"),
    ("10", "Time of use read (T_use)",                 "Agent_retrieves_document"),
    ("11", "Reasoning under injected context",         "Agent_acts_on_document"),
    ("12", "Prohibited tool call",                     "Agent_prohibited_tool_call"),
    ("13", "Response returned to the webapp",          "Agent_response_returned"),
]

TAB = chr(9)


def _durations(rows, stage):
    if stage == "_attacker":
        return [v for r in rows
                if (v := delta_ms(r, "attacker_modify_time", "attacker_modify_done")) is not None]
    if stage in START_SUBSTITUTE:
        return [v for r in rows
                if (v := delta_ms(r, START_SUBSTITUTE[stage], f"{stage}_end")) is not None]
    out = []
    for r in rows:
        raw = r.get(f"{stage}_ms", "")
        if raw not in ("", "None"):
            try:
                out.append(float(raw))
            except ValueError:
                pass
    return out


def table_step_durations(out_dir, runs):
    for run in runs:
        rows = run["rows"]
        head = ["Step", "Description", "Mean (ms)", "Trials"]
        lines = [TAB.join(head)]
        for num, desc, stage in ARROW_DURATIONS:
            vals = _durations(rows, stage)
            if vals:
                cells = [num, desc, f"{sum(vals)/len(vals):.2f}", str(len(vals))]
            else:
                cells = [num, desc, "", "0"]
            lines.append(TAB.join(cells))

        suffix = "" if len(runs) == 1 else "_" + re.sub(r"[^A-Za-z0-9]+", "", run["label"]).lower()
        name = f"table_step_durations{suffix}.txt"
        (out_dir / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("wrote", name)

        print(f"\n{run['label']} step durations")
        print(f"  {'step':>4}  {'description':<42} {'mean':>9} {'n':>6}")
        for num, desc, stage in ARROW_DURATIONS:
            vals = _durations(rows, stage)
            if vals:
                print(f"  {num:>4}  {desc:<42} {mean(vals):>9.2f} {len(vals):>6}")
            else:
                print(f"  {num:>4}  {desc:<42} {'-':>9} {0:>6}")

def _offsets(rows, col):
    return [v for r in rows
            if (v := delta_ms(r, "attacker_start_time", col)) is not None]


def table_step_times(out_dir, runs):
    for run in runs:
        rows = run["rows"]
        marks = [(num, desc,
                  "attacker_modify_time" if stage == "_attacker" else f"{stage}_start",
                  "attacker_modify_done" if stage == "_attacker" else f"{stage}_end")
                 for num, desc, stage in ARROW_DURATIONS]
        marks.append(("-", "T_check, window opens", "blob_read_time", "blob_read_time"))
        marks.append(("-", "T_use, window closes",
                      "Agent_retrieves_document_end", "Agent_retrieves_document_end"))

        head = ["Step", "Description", "Starts at (ms)", "Ends at (ms)", "Trials"]
        lines = [TAB.join(head)]
        for num, desc, a, b in marks:
            sv, ev = _offsets(rows, a), _offsets(rows, b)
            if sv and ev:
                cells = [num, desc,
                         f"{sum(sv)/len(sv):.2f}", f"{sum(ev)/len(ev):.2f}",
                         str(min(len(sv), len(ev)))]
            else:
                cells = [num, desc, "", "", "0"]
            lines.append(TAB.join(cells))

        suffix = "" if len(runs) == 1 else "_" + re.sub(r"[^A-Za-z0-9]+", "", run["label"]).lower()
        name = f"table_step_times{suffix}.txt"
        (out_dir / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("wrote", name)

        print(f"\n{run['label']} step times, ms from workflow_start")
        print(f"  {'step':>4}  {'description':<42} {'starts':>9} {'ends':>9} {'n':>6}")
        for num, desc, a, b in marks:
            sv, ev = _offsets(rows, a), _offsets(rows, b)
            if sv and ev:
                print(f"  {num:>4}  {desc:<42} {mean(sv):>9.2f} "
                      f"{mean(ev):>9.2f} {min(len(sv), len(ev)):>6}")
            else:
                print(f"  {num:>4}  {desc:<42} {'-':>9} {'-':>9} {0:>6}")

STANDALONE_TIMES = ["attacker_start_time", "blob_read_time",
                    "attacker_modify_time", "attacker_modify_done"]


def table_all_measurements(out_dir, runs):
    stages = [c[:-3] for c in runs[0]["rows"][0] if c.endswith("_ms")]

    def mean_dur(run, stage):
        vals = _durations(run["rows"], stage)
        return f"{sum(vals)/len(vals):.2f}" if vals else ""

    def mean_at(run, col):
        vals = _offsets(run["rows"], col)
        return sum(vals) / len(vals) if vals else None

    seq = {st: i for i, st in enumerate(stages)}
    when = {st: mean_at(runs[0], f"{st}_end") for st in stages}
    ordered = sorted(stages, key=lambda st: (when[st] is None, when[st] or 0.0, seq[st]))

    ov_when = mean_at(runs[0], "attacker_modify_done")

    def delay_range(run):
        ds = sorted({int(r["attacker_delay"]) for r in run["rows"]
                     if r["attacker_delay"] != ""})
        return f"{ds[0]} to {ds[-1]} ms, {len(ds)} values" if ds else ""

    def outcome_mix(run):
        counts = {}
        for r in run["rows"]:
            counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
        return ", ".join(f"{k} {v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1]))

    def overwrite_dur(run):
        vals = [v for r in run["rows"]
                if (v := delta_ms(r, "attacker_modify_time", "attacker_modify_done")) is not None]
        return f"{sum(vals)/len(vals):.2f}" if vals else ""

    def label(name):
        return name.replace("_", " ")

    lines = [TAB.join(["Measurement"] + [f"{run['label']} (ms)" for run in runs])]
    placed = False
    for st in ordered:
        if not placed and ov_when is not None and (when[st] or 0.0) > ov_when:
            lines.append(TAB.join([label("attacker_overwrite")] + [overwrite_dur(r) for r in runs]))
            placed = True
        lines.append(TAB.join([label(st)] + [mean_dur(run, st) for run in runs]))
    if not placed:
        lines.append(TAB.join([label("attacker_overwrite")] + [overwrite_dur(r) for r in runs]))

    base = {}
    for run in runs:
        marks = [mean_at(run, f"{st}_end") for st in stages]
        marks += [mean_at(run, c) for c in STANDALONE_TIMES]
        marks = [m for m in marks if m is not None]
        base[run["label"]] = -min(marks) if marks else 0.0
    for col in ("attacker_start_time", "blob_read_time"):
        cells = []
        for run in runs:
            v = mean_at(run, col)
            cells.append(f"{v + base[run['label']]:.2f}" if v is not None else "")
        lines.append(TAB.join([label(col)] + cells))
    lines.append(TAB.join([label("attacker_delay")] + [delay_range(run) for run in runs]))
    lines.append(TAB.join([label("outcome")] + [outcome_mix(run) for run in runs]))

    (out_dir / "table_all_measurements.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8")
    print("wrote table_all_measurements.txt",
          f"({len(stages)} stages + overwrite + 2 instants + 2, "
          f"{len(runs)} config{'s' if len(runs) > 1 else ''})")


def table_success_by_delay(out_dir, runs):
    for run in runs:
        by = {}
        for r in run["rows"]:
            d = r["_delay"]
            if d is None:
                continue
            hit = (r["_offset"] is not None and r["_t_scan"] is not None
                   and r["_t_use"] is not None
                   and r["_t_scan"] <= r["_offset"] <= r["_t_use"])
            k, h, n = by.get(d, (0, 0, 0))
            by[d] = (k + (r["outcome"] == "leak"), h + hit, n + 1)
        if not by:
            continue
        xs = sorted(by)
        _lo, use = measured_window(run)

        lines = ["Delay (ms)	Trials	In-window	P(hit)	Leaks	P(comply | hit)	Success rate"]
        for d in xs:
            k, h, n = by[d]
            comply = f"{k/h*100:.0f}%" if h else "-"
            lines.append(f"{d}	{n}	{h}	{h/n*100:.0f}%	{k}	{comply}	{k/n*100:.0f}%")

        suffix = "" if len(runs) == 1 else "_" + re.sub(r"[^A-Za-z0-9]+", "", run["label"]).lower()
        name = f"table_success_by_delay{suffix}.txt"
        (out_dir / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("wrote", name)

        rows_txt = []
        for d in xs:
            k, h, n = by[d]
            rows_txt.append((str(d), str(n), str(h), f"{h/n*100:.0f}%", str(k),
                             f"{k/h*100:.0f}%" if h else "—", f"{k/n*100:.0f}%"))
        headers = ("Delay (ms)", "Trials", "In-window", "P(hit)", "Leaks",
                   "P(comply | hit)", "Success rate")
        cols = (0.14, 0.26, 0.39, 0.49, 0.59, 0.78, 0.97)
        aligns = ("right",) * 7
        n_rows = len(rows_txt)
        fig, ax = plt.subplots(figsize=(8.6, 0.30 * (n_rows + 3.4)))
        fig.patch.set_facecolor(SURFACE)
        ax.set_facecolor(SURFACE)
        ax.set_xlim(0, 1)
        ax.set_ylim(0, n_rows + 2.8)
        ax.axis("off")
        ax.text(0.02, n_rows + 2.25, f"{run['label']}: success rate by attacker delay",
                fontsize=10, fontweight="bold", color=INK, va="center")
        for x, h, al in zip(cols, headers, aligns):
            ax.text(x, n_rows + 1.35, h, fontsize=8.6, fontweight="bold",
                    color=INK, ha=al, va="center")
        ax.plot([0.02, 0.98], [n_rows + 0.92, n_rows + 0.92], color=INK, linewidth=1.0)
        for i, row in enumerate(rows_txt):
            y = n_rows - i
            if i % 2:
                ax.add_patch(plt.Rectangle((0.02, y - 0.5), 0.96, 1.0,
                                           facecolor=GRID, alpha=0.35, linewidth=0))
            for x, cell, al in zip(cols, row, aligns):
                ax.text(x, y, cell, fontsize=8.4, color=INK, ha=al, va="center")
        ax.plot([0.02, 0.98], [0.5, 0.5], color=INK, linewidth=1.0)
        save(fig, out_dir, f"table_success_by_delay{suffix}.png")

        print(f"\n{run['label']}")
        print(f"  {'delay':>7} {'trials':>7} {'in-win':>7} {'P(hit)':>7} "
              f"{'leaks':>6} {'P(c|h)':>7} {'rate':>7}")
        for d in xs:
            k, h, n = by[d]
            comply = f"{k/h*100:>6.0f}%" if h else "   n/a"
            print(f"  {d:>7} {n:>7} {h:>7} {h/n*100:>6.0f}% {k:>6} {comply} "
                  f"{k/n*100:>6.0f}%")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print("usage: python figures.py [Label=]results.csv [[Label=]results.csv ...] [--out=DIR]")
        raise SystemExit(1)
    override = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--out=")), None)
    out = Path(override) if override else split_spec(args[0])[1].resolve().parent
    out.mkdir(parents=True, exist_ok=True)
    runs = [load(a) for a in args]

    fig_outcome_by_offset(out, runs)
    table_success_by_delay(out, runs)
    table_step_durations(out, runs)
    table_step_times(out, runs)
    table_all_measurements(out, runs)
    fig_step_timeline(out, runs)
    print(f"-> {out.resolve()}")

if __name__ == "__main__":
    main()
