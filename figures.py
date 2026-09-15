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

SEGMENTS = [
    ("Attacker Submit", "Document_lookup_start", "Document_lookup_end"),
    ("Blob fetch", "Blob_fetch_start", "Blob_fetch_end"),
    ("Security validation", "Initial_sec_validation_start", "Initial_sec_validation_end"),
    ("Mark SAFE", "Document_marked_safe_start", "Document_marked_safe_end"),
    ("Dispatch to agent", "Dispatch_to_agent_start", "Dispatch_to_agent_end"),
    ("LLM inference", "LLM_inference_start", "LLM_inference_end"),
    ("Agent checks SAFE state", "Agent_retrieves_document_state_start", "Agent_retrieves_document_state_end"),
    ("Document read", "Agent_retrieves_document_start", "Agent_retrieves_document_end"),
]

# Arrow numbers from the architecture diagram, appended to the y axis labels.
STEP_NUMBERS = {
    "Attacker Submit": "2",
    "Blob fetch": "3",
    "Security validation": "4",
    "Mark SAFE": "6",
    "Dispatch to agent": "7",
    "LLM inference": "8",
    "Agent checks SAFE state": "9",
    "Document read": "10",
}


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
        r["_offset"] = delta_ms(r, "attacker_start_time", "attacker_modify_time")
        r["_t_scan"] = (delta_ms(r, "attacker_start_time", "blob_read_time")
                    if r.get("blob_read_time")
                    else delta_ms(r, "attacker_start_time", "Initial_sec_validation_start"))
        r["_t_check"] = delta_ms(r, "attacker_start_time", ref) if ref else None
        r["_t_use"] = delta_ms(r, "attacker_start_time", "Agent_retrieves_document_start")
        r["_window"] = delta_ms(r, ref, "Agent_retrieves_document_start") if ref else None
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
    lo = median([r["_t_scan"] for r in run["rows"] if r["_t_scan"] is not None])
    hi = median([r["_t_use"] for r in run["rows"] if r["_t_use"] is not None])
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
        ax.set_xscale("symlog", linthresh=1, linscale=0.12)
        ax.set_xlim(left=0)
        ax.set_ylim(0, 1)
        ax.set_yticks([])

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
        fig, ax = new_fig(7.8, 0.55 * len(SEGMENTS) + 1.6)
        style_axes(ax, grid_axis="x")

        def stamps(col):
            return [v for v in (delta_ms(r, "attacker_start_time", col) for r in rows) if v is not None]

        right = 0.0
        sub_ms = False
        for i, (label, a, b) in enumerate(SEGMENTS):
            y = len(SEGMENTS) - 1 - i
            starts, ends = stamps(a), stamps(b)
            if not starts or not ends:
                continue
            s, e = median(starts), median(ends)
            q1, _m, q3 = quartiles(ends)
            ax.barh(y, e - s, left=s, height=0.55, color=RAMP[i % len(RAMP)],
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
                    sub_ms = True
            text = f"{dur:.2f} ms" if dur < 1.0 else f"{dur:.0f} ms"
            ax.annotate(text, xy=(label_x, y), xytext=(6, 0), textcoords="offset points",
                        va="center", ha="left", fontsize=8, color=INK)
            right = max(right, label_x)

        scan = median(stamps("Initial_sec_validation_start"))
        use = median(stamps(SEGMENTS[-1][1]))
        window = (use - scan) if (scan is not None and use is not None) else None
        log_scale = bool(window and window > 0 and right > window * 20)
        edge = right * (1.9 if log_scale else 1.16)
        if log_scale:
            ax.set_xscale("symlog", linthresh=1, linscale=0.12)
            ticks = [t for t in (0, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000) if t <= edge]
            ax.xaxis.set_major_locator(FixedLocator(ticks))
            ax.xaxis.set_minor_locator(FixedLocator([]))
            ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _p: f"{v:g}"))
        ax.set_xlim(0, edge)
        top = len(SEGMENTS) - 0.15
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

        anchor = next((i for i, (_l, a, _b) in enumerate(SEGMENTS)
                       if a == "Initial_sec_validation_start"), None)
        if scan is not None and anchor is not None:
            ay = len(SEGMENTS) - 1 - anchor + 0.42
            ax.plot([scan], [ay], marker="v", markersize=4.5, color=INK, zorder=6, clip_on=False)
            ax.annotate("start of TOCTOU window", xy=(scan, ay), xytext=(8, 0), textcoords="offset points", va="center", ha="left",
                        fontsize=7, color=INK_SOFT, zorder=6)

        ax.set_yticks(range(len(SEGMENTS)))
        ax.set_yticklabels([step_label(l) for l, _a, _b in reversed(SEGMENTS)], fontsize=8.5)
        ax.set_xlabel("Time (ms)" if log_scale else "Time (ms)",
                      fontsize=9, color=INK_SOFT)
        ax.set_ylim(-0.6, top + 0.55)
        ax.set_title(f"Step Timeline",
                     fontsize=9.5, color=INK)
        if sub_ms:
            ax.text(1.0, -0.115, "sub-millisecond steps shown as the mean across trials",
                    transform=ax.transAxes, ha="right", va="top", fontsize=7, color=INK_MUTED)
        suffix = "" if len(runs) == 1 else "_" + re.sub(r"[^A-Za-z0-9]+", "", run["label"]).lower()
        save(fig, out_dir, f"fig_step_timeline{suffix}.png")


def table_success_by_delay(out_dir, runs):
    for run in runs:
        by = {}
        for r in run["rows"]:
            d = r["_delay"]
            if d is None:
                continue
            k, n = by.get(d, (0, 0))
            by[d] = (k + (r["outcome"] == "leak"), n + 1)
        if not by:
            continue
        xs = sorted(by)
        ns0 = by[xs[0]][1]
        _lo, use = measured_window(run)

        lines = []
        lines.append(r"\begin{table}[ht]")
        lines.append(r"\centering")
        lines.append(r"\begin{tabular}{rrrr}")
        lines.append(r"\hline")
        lines.append(r"Delay (ms) & Trials & Leaks & Success rate \\")
        lines.append(r"\hline")
        for d in xs:
            k, n = by[d]
            lines.append(f"{d} & {n} & {k} & {k/n*100:.0f}\\% \\\\")
        lines.append(r"\hline")
        lines.append(r"\end{tabular}")
        cap = f"Exploitation success rate by attacker delay, {run['label']} configuration."
        if use is not None:
            cap += f" Measured check-to-use interval closes at {use:.0f}~ms."
        lines.append(r"\caption{" + cap + "}")
        lines.append(r"\label{tab:success-" + re.sub(r"[^A-Za-z0-9]+", "", run["label"]).lower() + "}")
        lines.append(r"\end{table}")

        suffix = "" if len(runs) == 1 else "_" + re.sub(r"[^A-Za-z0-9]+", "", run["label"]).lower()
        name = f"table_success_by_delay{suffix}.tex"
        (out_dir / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("wrote", name)

        rows_txt = [(str(d), str(by[d][1]), str(by[d][0]), f"{by[d][0]/by[d][1]*100:.0f}%") for d in xs]
        headers = ("Delay (ms)", "Trials", "Leaks", "Success rate")
        cols = (0.22, 0.44, 0.62, 0.88)
        aligns = ("right", "right", "right", "right")
        n_rows = len(rows_txt)
        fig, ax = plt.subplots(figsize=(6.0, 0.30 * (n_rows + 3.4)))
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
        note = f"n = {ns0} trials per point" if len({by[d][1] for d in xs}) == 1 else "trials per point vary"
        if use is not None:
            note += f"; check-to-use interval closes at {use:.0f} ms"
        ax.text(0.02, 0.05, note, fontsize=7.2, color=INK_MUTED, va="center")
        save(fig, out_dir, f"table_success_by_delay{suffix}.png")

        print(f"\n{run['label']}")
        print(f"  {'delay':>7} {'trials':>7} {'leaks':>6} {'rate':>7}")
        for d in xs:
            k, n = by[d]
            print(f"  {d:>7} {n:>7} {k:>6} {k/n*100:>6.0f}%")


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
    fig_step_timeline(out, runs)
    print(f"-> {out.resolve()}")


if __name__ == "__main__":
    main()
