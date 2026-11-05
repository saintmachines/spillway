#!/usr/bin/env python3
"""Print the README's benchmark tables from benchmarks/results/*.json and check them against the paper.

    python benchmarks/scripts/make_tables.py                  # print, check, write benchmarks/TABLES.md
    python benchmarks/scripts/make_tables.py --no-write       # print and check only
    python benchmarks/scripts/make_tables.py --results DIR --out FILE

Every printed value is read or computed from the released result files, except that ROPE's two ChatInject composites
use the benign utility the paper prints (ROPE_BENIGN_CHATINJECT below). The expected values are the paper's printed
numbers (Tables 1 to 4, Appendix Table 8, and the values Figures 3 and 4 plot), copied here verbatim, so the script
is also a test: it exits 1 when a computed value differs from the paper at the printed precision.

Scoring conventions (paper Sec. 4): BU = benign utility, UAU = utility under attack, ASR = in-scope attack success
(executed effect, content-manipulation tasks dropped). NRP = BU x (1 - ASR), printed NRP (BU) in Table 2 beside
NRP (UAU) = UAU x (1 - ASR); ERS = harmonic mean of (1 - ASR) and BU.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS_DIR = HERE.parent / "results"
OUT_FILE = HERE.parent / "TABLES.md"

SUITES = ("banking", "slack", "travel", "workspace")
BACKBONES = ("gpt-4o-mini", "qwen3-coder:30b", "qwen3:8b")
METHODS = (
    ("undefended", "Undefended"),
    ("spillway", "SPILLWAY"),
    ("melon", "MELON"),
    ("progent", "Progent"),
    ("drift", "DRIFT"),
    ("rope", "ROPE"),
    ("spotlighting", "Spotlighting"),
    ("pi_detector", "PI detector"),
)
LABEL = {
    "banking": "Banking",
    "slack": "Slack",
    "travel": "Travel",
    "workspace": "Workspace",
    "github": "GitHub",
    "dailylife": "DailyLife",
    "shopping": "Shopping",
}

# --------------------------------------------------------------------------- expected values (verbatim from the tex)

# Table 1 (tab:main-grid). Per row: BU/UAU and ASR for Undefended, SPILLWAY, MELON, Progent, DRIFT, ROPE,
# Spotlighting, PI detector. The last row is the twelve-cell mean.
PAPER_TABLE1 = r"""
banking gpt-4o-mini & .562/.424 & .556 & \textbf{.562/.521} & \textbf{.000} & .438/.306 & .049 & .375/.299 & .097 & .438/.431 & .111 & .438/.431 & .000 & .500/.431 & .549 & .500/.375 & .118 \\
banking qwen3-coder:30b & .375/.486 & .299 & \textbf{.375/.500} & \textbf{.000} & .375/.299 & .125 & .312/.354 & .056 & .688/.542 & .014 & .375/.375 & .000 & .375/.410 & .382 & .500/.424 & .097 \\
banking qwen3:8b & .500/.403 & .181 & \textbf{.438/.438} & \textbf{.000} & .500/.403 & .215 & .375/.361 & .000 & .562/.410 & .028 & .438/.438 & .000 & .562/.431 & .188 & .438/.340 & .083 \\
slack gpt-4o-mini & .762/.514 & .629 & \textbf{.714/.524} & \textbf{.000} & .714/.133 & .000 & .667/.400 & .076 & .714/.486 & .000 & .524/.343 & .019 & .619/.524 & .562 & .238/.162 & .086 \\
slack qwen3-coder:30b & .667/.467 & .724 & \textbf{.571/.429} & \textbf{.000} & .667/.190 & .076 & .476/.362 & .010 & .286/.276 & .000 & .429/.276 & .019 & .524/.390 & .581 & .190/.171 & .124 \\
slack qwen3:8b & .619/.419 & .448 & \textbf{.476/.286} & \textbf{.000} & .571/.362 & .457 & .190/.105 & .019 & .429/.314 & .010 & .333/.200 & .019 & .429/.295 & .467 & .190/.162 & .086 \\
travel gpt-4o-mini & .500/.336 & .229 & \textbf{.550/.571} & \textbf{.000} & .550/.300 & .000 & .550/.529 & .029 & .400/.607 & .000 & .350/.350 & .000 & .600/.429 & .179 & .300/.107 & .014 \\
travel qwen3-coder:30b & .500/.414 & .129 & \textbf{.500/.407} & \textbf{.000} & .550/.393 & .029 & .450/.414 & .007 & .100/.443 & .000 & .250/.264 & .000 & .550/.414 & .136 & .250/.200 & .000 \\
travel qwen3:8b & .250/.229 & .229 & \textbf{.250/.343} & \textbf{.000} & .250/.186 & .157 & .150/.164 & .036 & .300/.264 & .000 & .200/.157 & .000 & .300/.171 & .150 & .050/.050 & .000 \\
workspace gpt-4o-mini & .825/.398 & .184 & \textbf{.875/.838} & \textbf{.000} & .775/.330 & .002 & .800/.621 & .041 & .525/.607 & .009 & .625/.539 & .000 & .825/.430 & .148 & .625/.254 & .070 \\
workspace qwen3-coder:30b & .500/.480 & .036 & \textbf{.475/.543} & \textbf{.000} & .500/.430 & .004 & .475/.482 & .002 & .575/.530 & .002 & .400/.420 & .000 & .600/.452 & .039 & .425/.275 & .025 \\
workspace qwen3:8b & .425/.434 & .020 & \textbf{.450/.414} & \textbf{.000} & .425/.441 & .011 & .425/.366 & .004 & .500/.523 & .014 & .375/.352 & .000 & .450/.457 & .020 & .275/.243 & .014 \\
mean & .540/.417 & .305 & \textbf{.520/.484} & \textbf{.000} & .526/.314 & .094 & .437/.371 & .031 & .460/.453 & .016 & .395/.345 & .005 & .528/.403 & .283 & .332/.230 & .060 \\
"""

# Table 2 (tab:triple): BU, UAU, ASR, NRP (BU), NRP (UAU), ERS, cells with a raw hit, filter-zeroed cells, cells
# leaking in-scope. NRP (UAU) = UAU x (1 - ASR), the form MSB uses; the paper cites it in the caption.
PAPER_TABLE2 = r"""
Undefended & .540 & .417 & .305 & .375 & .290 & .608 & 12 & 0 & 12 \\
\textbf{SPILLWAY} & \textbf{.520} & \textbf{.484} & \textbf{.000} & \textbf{.520} & \textbf{.484} & \textbf{.684} & \textbf{0} & \textbf{0} & \textbf{0} \\
MELON & .526 & .314 & .094 & .477 & .284 & .666 & 11 & 1 & 10 \\
Progent & .437 & .371 & .031 & .423 & .359 & .602 & 11 & 0 & 11 \\
DRIFT & .460 & .453 & .016 & .453 & .446 & .627 & 7 & 0 & 7 \\
ROPE & .395 & .345 & .005 & .393 & .343 & .566 & 6 & 3 & 3 \\
Spotlighting & .528 & .403 & .283 & .379 & .289 & .608 & 12 & 0 & 12 \\
PI detector & .332 & .230 & .060 & .312 & .216 & .491 & 10 & 0 & 10 \\
"""

# Table 3 (tab:ingress-ablation): UAU / ASR on Banking, Slack, Travel, Workspace (qwen3:8b).
PAPER_TABLE3 = r"""
Floor & .333 / .000 & .181 / .000 & .243 / .000 & .445 / .000 \\
Floor + judge & .375 / .028 & .190 / .000 & .243 / .000 & .439 / .002 \\
Floor + sanitizer & .375 / .000 & .286 / .000 & .343 / .000 & .412 / .000 \\
\textbf{SPILLWAY} (all) & \textbf{.438} / \textbf{.000} & \textbf{.286} / \textbf{.000} & \textbf{.343} / \textbf{.000} & \textbf{.414} / \textbf{.000} \\
SPILLWAY, no span veto & .438 / .000 & .286 / .000 & .343 / .000 & .418 / .000 \\
"""

# Table 4 (tab:rope-chatinject), the ChatInject panel: Workspace UAU, ASR; Slack UAU, ASR; NRP; ERS (qwen3:8b).
PAPER_TABLE4_CHATINJECT = r"""
Undefended & $.052$ & $.245$ & $.095$ & $.648$ & $.269$ & $.496$
\textbf{SPILLWAY} & \textbf{.371} & \textbf{.000} & \textbf{.286} & \textbf{.000} & \textbf{.463} & \textbf{.633}
MELON & $.084$ & $.020$ & $.095$ & $.000$ & $.494$ & $.660$
Progent$^{\ddagger}$ & $.161$ & $.005$ & $.057$ & $.010$ & $.305$ & $.457$
DRIFT$^{\dagger}$ & $.393$ & $.062$ & $.352$ & $.019$ & $.445$ & $.625$
ROPE$^{\ddagger}$ & $.157$ & $.002$ & $.162$ & $.095$ & $.292$ & $.462$
Spotlighting & $.191$ & $.013$ & $.076$ & $.181$ & $.398$ & $.591$
PI detector & $.050$ & $.021$ & $.162$ & $.000$ & $.230$ & $.374$
"""

# Appendix Table 8 (tab:app-ropemini), the per-suite values of Figure 4: UAU / ASR for SPILLWAY, ROPE with its
# authors' Claude Opus 4.8 router, ROPE with the agent's own model (gpt-4o-mini) as router.
PAPER_TABLE8 = r"""
Banking & .521 / .000 & .438 / .000 & .431 / .000 \\
Slack & .524 / .000 & .514 / .048 & .343 / .019 \\
Travel & .571 / .000 & .500 / .000 & .350 / .000 \\
Workspace & .838 / .000 & .670 / .000 & .539 / .000 \\
GitHub & .600 / .000 & .500 / .000 & .383 / .000 \\
DailyLife & .435 / .000 & .295 / .010 & .150 / .000 \\
Shopping & .383 / .000 & .361 / .044 & .333 / .072 \\
Mean & .553 / .000 & .468 / .015 & .361 / .013 \\
NRP (UAU) & \textbf{.553} & .462 & .357 \\
ERS (UAU) & \textbf{.703} & .627 & .519 \\
"""

# Figure 3 (fig:position-cost) as the paper's text states it (Sec. 5, "Cost"): added model calls per benign
# episode on qwen3:8b, and added wall-clock in seconds, Slack / Workspace. SPILLWAY's episodes were "within 0.5 s"
# of the undefended agent's, and its judge is consulted 0.05 (Workspace) and 0.43
# (Slack) times per episode.
PAPER_FIG2_CALLS = {"MELON": (5.29, 3.25), "Progent": (8.67, 5.94), "DRIFT": (9.91, 9.59), "SPILLWAY": (0.39, 0.19)}
PAPER_FIG2_SECONDS = {"MELON": (4.9, 7.9), "Progent": (1.6, 2.3), "DRIFT": (9.9, 10.5)}
PAPER_FIG2_SPILLWAY_WITHIN_S = 0.5
PAPER_JUDGE_CALLS_PER_EPISODE = {"workspace": 0.05, "slack": 0.43}

# ROPE's ChatInject row runs without its clamp, which is on in Table 1, so the paper (Appendix A) gives the benign
# utility from a run in that setting: Workspace .325 and Slack .286, i.e. 13 of 40 and 6 of 21 user tasks. The
# composites use these values as printed, as for every other row.
ROPE_BENIGN_CHATINJECT = {"workspace": 13 / 40, "slack": 6 / 21}

FLOAT_RE = re.compile(r"\.\d{3}")
INT_RE = re.compile(r"(?<![.\d])\d+(?![.\d])")


def tex_rows(block: str) -> list[tuple[str, list[str]]]:
    """(label, printed floats) per non-empty row of a verbatim tex block."""
    rows = []
    for line in block.strip().splitlines():
        label, _, rest = line.partition("&")
        rows.append((re.sub(r"\\textbf|[{}$^]|\\d?dagger|\(all\)", "", label).strip(), FLOAT_RE.findall(rest)))
    return rows


# --------------------------------------------------------------------------- arithmetic


def f3(x: float) -> str:
    return f"{x:.3f}"


def r3(x: float) -> float:
    """The value as printed with three decimals."""
    return float(f3(x))


def nrp(bu: float, asr: float) -> float:
    return bu * (1.0 - asr)


def ers(bu: float, asr: float) -> float:
    robust = 1.0 - asr
    return 0.0 if robust + bu == 0 else 2.0 * robust * bu / (robust + bu)


def mean(values: list[float]) -> float:
    return sum(values) / len(values)


class Checker:
    """Collects (what, computed, expected) comparisons; a mismatch is any pair that differs at the printed precision."""

    def __init__(self) -> None:
        self.n = 0  # every check: the printed values compared (n_eq) and the consistency checks on the stored files
        self.n_eq = 0
        self.mismatches: list[str] = []

    def eq(self, what: str, got: str, expected: str) -> None:
        self.n += 1
        self.n_eq += 1
        if abs(float(got) - float(expected)) > 1e-9:
            self.mismatches.append(f"{what}: computed {got}, paper {expected}")

    def true(self, what: str, ok: bool, detail: str = "") -> None:
        self.n += 1
        if not ok:
            self.mismatches.append(f"{what}: {detail}")


# --------------------------------------------------------------------------- loading


def load(results: Path) -> dict:
    def read(name: str) -> dict:
        path = results / name
        if not path.is_file():
            raise SystemExit(f"make_tables.py: missing result file {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    return {
        "cells": read("breadth_grid_cells.json"),
        "summary": read("breadth_grid_summary.json"),
        "ablation": read("ablation_and_chatinject.json"),
        "no_span_veto": read("ablation_no_span_veto.json"),
        "opus": read("delegated_routing_opus_router.json"),
        "agent": read("delegated_routing_agent_router.json"),
        "cost": read("fig_cost_values.json"),
    }


# --------------------------------------------------------------------------- markdown


def md_table(headers: list[str], rows: list[list[str]], bold_rows: set[int] = frozenset()) -> str:
    def cell(text: str, bold: bool) -> str:
        return f"**{text}**" if bold and text and text != "-" else text

    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for i, row in enumerate(rows):
        out.append("| " + " | ".join(cell(c, i in bold_rows) for c in row) + " |")
    return "\n".join(out)


# --------------------------------------------------------------------------- tables


def table_summary(data: dict, check: Checker) -> str:
    """Twelve-cell summary (paper Table 2). Composites from the printed three-decimal means, as in the paper."""
    t2 = data["summary"]["table2"]
    benign, attacked = data["cells"]["benign"], data["summary"]["cells"]
    expected = dict(tex_rows(PAPER_TABLE2))
    expected_counts = {
        re.sub(r"\\textbf|[{}]", "", line.split("&")[0]).strip(): INT_RE.findall(line.split("&", 7)[-1])
        for line in PAPER_TABLE2.strip().splitlines()
    }
    rows = []
    for key, name in METHODS:
        row = t2[key]
        # The file's means must equal the means of its own twelve per-cell values (one fact, stored twice).
        bu_cells = [benign[f"{bb}|{s}"][key]["util"] for bb in BACKBONES for s in SUITES]
        uau_cells = [attacked[f"{bb}|{s}|{key}"]["util"] for bb in BACKBONES for s in SUITES]
        asr_cells = [attacked[f"{bb}|{s}|{key}"]["asr"] for bb in BACKBONES for s in SUITES]
        for label, file_value, cell_mean in (
            ("BU", row["benign_util"], mean(bu_cells)),
            ("UAU", row["util"], mean(uau_cells)),
            ("ASR", row["asr"], mean(asr_cells)),
        ):
            check.true(
                f"Table 2 {name} {label}: summary file vs mean of the 12 cells",
                abs(file_value - cell_mean) < 1e-9,
                f"{file_value!r} vs {cell_mean!r}",
            )
        bu, uau, asr = r3(row["benign_util"]), r3(row["util"]), r3(row["asr"])
        values = [f3(bu), f3(uau), f3(asr), f3(nrp(bu, asr)), f3(nrp(uau, asr)), f3(ers(bu, asr))]
        counts = [str(row["raw_hit_cells"]), str(row["content_manip_cells"]), str(row["real_leak_cells"])]
        for col, got, exp in zip(("BU", "UAU", "ASR", "NRP (BU)", "NRP (UAU)", "ERS"), values, expected[name]):
            check.eq(f"Table 2 {name} {col}", got, exp)
        for col, got, exp in zip(("raw-hit cells", "filter-zeroed", "in-scope leak"), counts, expected_counts[name]):
            check.eq(f"Table 2 {name} {col}", got, exp)
        rows.append([name, *values, *counts])
    headers = [
        "Method",
        "BU",
        "UAU",
        "ASR",
        "NRP (BU)",
        "NRP (UAU)",
        "ERS",
        "raw-hit cells",
        "filter-zeroed",
        "in-scope leak",
    ]
    return md_table(headers, rows, bold_rows={1})


def table_per_cell(data: dict, check: Checker, notes: list[str]) -> str:
    """Per-cell BU/UAU and ASR (paper Table 1).

    BU comes from the benign block of breadth_grid_cells.json (its only source). UAU and ASR come from the per-cell
    block of breadth_grid_summary.json, the file whose twelve-cell means the paper's Table 2 prints; every cell is
    also compared with breadth_grid_cells.json and a difference is reported in the data notes.
    """
    cells, benign = data["cells"]["cells"], data["cells"]["benign"]
    attacked = data["summary"]["cells"]
    t2 = data["summary"]["table2"]
    expected = dict(tex_rows(PAPER_TABLE1))
    rows, bold = [], set()
    for suite in SUITES:
        for bb in BACKBONES:
            values = []
            for key, name in METHODS:
                a, b = cells[f"{bb}|{suite}"][key], attacked[f"{bb}|{suite}|{key}"]
                for field in ("util", "asr"):
                    if abs(a[field] - b[field]) > 1e-9:
                        notes.append(
                            f"{LABEL[suite]}, {bb}, {name}, {'UAU' if field == 'util' else 'ASR'}: printed {f3(b[field])} "
                            f"({b.get('inscope_hits')} in-scope hits of {b['scored']} in breadth_grid_summary.json, as in the "
                            "paper's Table 1, Appendix Table 5 and the Table 2 mean); breadth_grid_cells.json counts "
                            f"{a.get('hits')} hits ({f3(a[field])})."
                        )
                values += [f"{f3(benign[f'{bb}|{suite}'][key]['util'])}/{f3(b['util'])}", f3(b["asr"])]
            printed = [v for pair in values[0::2] for v in pair.split("/")]
            flat = []
            for i in range(len(METHODS)):
                flat += [printed[2 * i], printed[2 * i + 1], values[2 * i + 1]]
            for (key, name), j in zip(METHODS, range(0, 3 * len(METHODS), 3)):
                for col, got, exp in zip(("BU", "UAU", "ASR"), flat[j : j + 3], expected[f"{suite} {bb}"][j : j + 3]):
                    check.eq(f"Table 1 {LABEL[suite]} {bb} {name} {col}", got, exp)
            rows.append([LABEL[suite], bb, *values])
    values = []
    for key, _ in METHODS:
        values += [f"{f3(t2[key]['benign_util'])}/{f3(t2[key]['util'])}", f3(t2[key]["asr"])]
    flat = []
    for i in range(len(METHODS)):
        flat += [*values[2 * i].split("/"), values[2 * i + 1]]
    for (key, name), j in zip(METHODS, range(0, 3 * len(METHODS), 3)):
        for col, got, exp in zip(("BU", "UAU", "ASR"), flat[j : j + 3], expected["mean"][j : j + 3]):
            check.eq(f"Table 1 mean {name} {col}", got, exp)
    rows.append(["*mean*", "*12 cells*", *values])
    headers = ["Suite", "Backbone"]
    for _, name in METHODS:
        headers += [f"{name} BU/UAU", f"{name} ASR"]
    return md_table(headers, rows, bold_rows=bold)


def table_ablation(data: dict, check: Checker) -> str:
    """Component ablation on qwen3:8b (paper Table 3)."""
    t3 = data["ablation"]["table3"]
    nsv = data["no_span_veto"]["cells"]
    arms = (
        ("spwabl_floor", "Floor"),
        ("spwabl_panel", "Floor + judge"),
        ("spwabl_ingress", "Floor + sanitizer"),
        ("spwplus", "SPILLWAY (all)"),
    )
    expected = dict(tex_rows(PAPER_TABLE3))
    rows = []
    for key, name in arms:
        values = [f"{f3(t3[f'{key}|{s}']['util'])} / {f3(t3[f'{key}|{s}']['asr_exec'])}" for s in SUITES]
        flat = [v for pair in values for v in pair.split(" / ")]
        for suite, j in zip(SUITES, range(0, 8, 2)):
            check.eq(f"Table 3 {name} {LABEL[suite]} UAU", flat[j], expected[name.replace(" (all)", "")][j])
            check.eq(f"Table 3 {name} {LABEL[suite]} ASR", flat[j + 1], expected[name.replace(" (all)", "")][j + 1])
        rows.append([name, *values])
    values = [f"{f3(nsv[s]['util'])} / {f3(nsv[s]['inscope_asr'])}" for s in SUITES]
    flat = [v for pair in values for v in pair.split(" / ")]
    for suite, j in zip(SUITES, range(0, 8, 2)):
        check.eq(f"Table 3 no span veto {LABEL[suite]} UAU", flat[j], expected["SPILLWAY, no span veto"][j])
        check.eq(f"Table 3 no span veto {LABEL[suite]} ASR", flat[j + 1], expected["SPILLWAY, no span veto"][j + 1])
    check.true(
        "Table 3 no span veto: would-be-vetoed calls",
        data["no_span_veto"]["would_be_vetoed_calls"] == 0,
        f"{data['no_span_veto']['would_be_vetoed_calls']}",
    )
    rows.append(["SPILLWAY, no span veto", *values])
    headers = ["Arm", *(f"{LABEL[s]} UAU / ASR" for s in SUITES)]
    return md_table(headers, rows, bold_rows={3})


def table_chatinject(data: dict, check: Checker) -> tuple[str, list[str]]:
    """ChatInject panel on qwen3:8b (paper Table 4, left). Composites per suite from the printed values, then averaged.

    BU is the method's Table 1 value on the qwen3:8b cell; ROPE, run here without its clamp, uses a benign run in
    that setting.
    """
    panel = data["ablation"]["table4_rows"]["unified_v122"]
    benign = data["cells"]["benign"]
    expected = dict(tex_rows(PAPER_TABLE4_CHATINJECT))
    order = (
        ("undefended", "Undefended"),
        ("spillway", "SPILLWAY"),
        ("melon", "MELON"),
        ("progent", "Progent"),
        ("drift", "DRIFT"),
        ("rope", "ROPE"),
    )
    rows, missing = [], []
    for key, name in order:
        if key not in panel:
            missing.append(name)
            continue
        per_suite_nrp, per_suite_ers, values = [], [], []
        for suite in ("workspace", "slack"):
            block = panel[key][suite]
            check.true(
                f"Table 4 {name} {LABEL[suite]} complete",
                block["complete"] and block["scored"] == block["grid"],
                f"{block['scored']}/{block['grid']}",
            )
            uau, asr = r3(block["util_grid"]), r3(block["asr_exec_grid"])
            bu = r3(ROPE_BENIGN_CHATINJECT[suite]) if key == "rope" else r3(benign[f"qwen3:8b|{suite}"][key]["util"])
            per_suite_nrp.append(nrp(bu, asr))
            per_suite_ers.append(ers(bu, asr))
            values += [f3(uau), f3(asr)]
        values += [f3(mean(per_suite_nrp)), f3(mean(per_suite_ers))]
        for col, got, exp in zip(
            ("Workspace UAU", "Workspace ASR", "Slack UAU", "Slack ASR", "NRP", "ERS"), values, expected[name]
        ):
            check.eq(f"Table 4 ChatInject {name} {col}", got, exp)
        rows.append([name, *values])
    not_released = [name for name in ("Spotlighting", "PI detector") if name in expected]
    headers = ["Method", "Workspace UAU", "Workspace ASR", "Slack UAU", "Slack ASR", "NRP", "ERS"]
    return md_table(headers, rows, bold_rows={1}), missing + not_released


def table_delegated(data: dict, check: Checker) -> str:
    """Delegated-routing grid vs ROPE on gpt-4o-mini (paper Figure 4, Appendix Table 8).

    One run per suite (seed 42); the mean is unweighted over the seven suites. NRP (UAU) and ERS (UAU) are per-suite
    composites with UAU standing in for BU (the AgentDyn suites have no benign run), macro-averaged over the seven suites.
    """
    opus, agent = data["opus"], data["agent"]
    suites = ("banking", "slack", "travel", "workspace", "github", "dailylife", "shopping")

    def spillway(suite: str) -> dict:
        return opus["a4_scores"][suite] if suite in SUITES else opus["scores"][f"spw_full_s42_{suite}"]

    columns = (
        ("SPILLWAY", spillway),
        ("ROPE (Opus 4.8 router)", lambda s: opus["scores"][f"rope_s42_{s}"]),
        ("ROPE (gpt-4o-mini router)", lambda s: agent["scores"][f"rope_s42_{s}"]),
    )
    expected = dict(tex_rows(PAPER_TABLE8))
    rows = []
    stats = {name: {"uau": [], "asr": []} for name, _ in columns}
    for suite in suites:
        values = []
        for name, get in columns:
            score = get(suite)
            check.true(
                f"Table 8 {name} {LABEL[suite]} complete",
                score["complete"] and score["scored"] == score["grid"],
                f"{score['scored']}/{score['grid']}",
            )
            stats[name]["uau"].append(score["util"])
            stats[name]["asr"].append(score["inscope_asr"])
            values.append(f"{f3(score['util'])} / {f3(score['inscope_asr'])}")
        flat = [v for pair in values for v in pair.split(" / ")]
        for (name, _), j in zip(columns, range(0, 6, 2)):
            check.eq(f"Table 8 {LABEL[suite]} {name} UAU", flat[j], expected[LABEL[suite]][j])
            check.eq(f"Table 8 {LABEL[suite]} {name} ASR", flat[j + 1], expected[LABEL[suite]][j + 1])
        rows.append([LABEL[suite], *values])
    means, nrps, erss = [], [], []
    for name, _ in columns:
        uau, asr = stats[name]["uau"], stats[name]["asr"]
        means.append(f"{f3(mean(uau))} / {f3(mean(asr))}")
        nrps.append(f3(mean([nrp(u, a) for u, a in zip(uau, asr)])))
        erss.append(f3(mean([ers(u, a) for u, a in zip(uau, asr)])))
    flat = [v for pair in means for v in pair.split(" / ")]
    for (name, _), j in zip(columns, range(0, 6, 2)):
        check.eq(f"Table 8 mean {name} UAU", flat[j], expected["Mean"][j])
        check.eq(f"Table 8 mean {name} ASR", flat[j + 1], expected["Mean"][j + 1])
    for (name, _), got_n, got_e, exp_n, exp_e in zip(columns, nrps, erss, expected["NRP (UAU)"], expected["ERS (UAU)"]):
        check.eq(f"Table 8 NRP (UAU) {name}", got_n, exp_n)
        check.eq(f"Table 8 ERS (UAU) {name}", got_e, exp_e)
    rows += [["*Mean*", *means], ["*NRP (UAU)*", *nrps], ["*ERS (UAU)*", *erss]]
    headers = ["Suite", *(name + " UAU / ASR" for name, _ in columns)]
    return md_table(headers, rows)


def table_cost(data: dict, check: Checker) -> str:
    """Per-episode cost on qwen3:8b benign traffic (paper Figure 3): added model calls and added wall-clock."""
    cost = data["cost"]
    benign = data["cells"]["benign"]
    rows = []
    for name in ("SPILLWAY", "MELON", "Progent", "DRIFT"):
        values = []
        for suite in ("workspace", "slack"):
            seconds, calls = cost[suite][name]
            values += [f"{calls:.2f}", f"{seconds:+.1f}"]
            idx = 1 if suite == "workspace" else 0  # the paper states Slack first
            check.eq(
                f"Figure 3 {name} {LABEL[suite]} added calls", f"{calls:.2f}", f"{PAPER_FIG2_CALLS[name][idx]:.2f}"
            )
            if name in PAPER_FIG2_SECONDS:
                check.eq(
                    f"Figure 3 {name} {LABEL[suite]} added seconds",
                    f"{seconds:.1f}",
                    f"{PAPER_FIG2_SECONDS[name][idx]:.1f}",
                )
            else:
                check.true(
                    f"Figure 3 {name} {LABEL[suite]} within {PAPER_FIG2_SPILLWAY_WITHIN_S} s",
                    abs(seconds) <= PAPER_FIG2_SPILLWAY_WITHIN_S,
                    f"{seconds:+.2f} s",
                )
        rows.append([name, *values])
    judge = {s: benign[f"qwen3:8b|{s}"]["spillway"]["judge_calls_per_episode"] for s in SUITES}
    for suite, exp in PAPER_JUDGE_CALLS_PER_EPISODE.items():
        check.eq(f"judge calls per benign episode {LABEL[suite]}", f"{judge[suite]:.2f}", f"{exp:.2f}")
    headers = ["Method", "Workspace added calls", "Workspace added s", "Slack added calls", "Slack added s"]
    table = md_table(headers, rows, bold_rows={0})
    judge_line = ", ".join(f"{LABEL[s]} {judge[s]:.2f}" for s in SUITES)
    return (
        table
        + f"\n\nSPILLWAY's judge is consulted per benign episode: {judge_line} (its calls are included in the added calls above)."
    )


# --------------------------------------------------------------------------- document


def build(results: Path) -> tuple[str, Checker]:
    data = load(results)
    check = Checker()
    notes: list[str] = []
    sections = []
    sections.append(
        (
            "AgentDojo breadth grid, twelve-cell summary (paper Table 2)",
            "Means over 3 backbones x 4 suites under the standard attack (suite v1.2.2, full grid). SPILLWAY is the only "
            "method with no in-scope hit on any of the twelve cells, at the highest utility under attack. The collision "
            "filter zeroes no cell; the content-manipulation filter zeroes one MELON cell and ROPE's three Travel cells.",
            table_summary(data, check),
        )
    )
    sections.append(
        (
            "Per-cell results (paper Table 1)",
            "BU/UAU and in-scope ASR per cell. Averaged over the three backbones, SPILLWAY's mean UAU exceeds the undefended "
            "reference on Workspace, Banking and Travel, because the sanitizer removes an injection that would otherwise derail "
            "the agent before it reads it.",
            table_per_cell(data, check, notes),
        )
    )
    sections.append(
        (
            "Component ablation on qwen3:8b (paper Table 3)",
            "UAU / ASR (executed effect) per suite, 949 pairs per arm. The floor alone holds every suite at zero, and the "
            "sanitizer lifts Slack and Travel utility.",
            table_ablation(data, check),
        )
    )
    chatinject, not_in_results = table_chatinject(data, check)
    note = ""
    if not_in_results:
        note = f" Rows for {', '.join(not_in_results)}: the paper's Table 4."
    sections.append(
        (
            "ChatInject stress panel on qwen3:8b (paper Table 4, left)",
            "Forged chat-template injections, 560 Workspace and 105 Slack pairs. SPILLWAY has no raw hit in any pair and "
            "recovers part of the utility the hijack destroys. NRP/ERS use each method's Table 1 benign utility (ROPE: a "
            "benign run without its clamp), per suite, then the mean of the two suites." + note,
            chatinject,
        )
    )
    sections.append(
        (
            "Delegated-routing grid vs ROPE on gpt-4o-mini (paper Figure 4, Appendix Table 8)",
            "AgentDojo v1.2.2 (first four rows) and AgentDyn (last three), standard attack, full grid, one run per suite. "
            "SPILLWAY holds in-scope ASR at zero on all seven suites and has the higher utility on every suite under "
            "either ROPE router.",
            table_delegated(data, check),
        )
    )
    sections.append(
        (
            "Cost per benign episode on qwen3:8b (paper Figure 3)",
            "Added model invocations per episode over the undefended agent (backbone plus any defense model; for "
            "SPILLWAY the defense model is its local judge) and added wall-clock in seconds on the paper's GPU, which "
            "depends on the serving stack. SPILLWAY's wall-clock was timed in a separate session.",
            table_cost(data, check),
        )
    )
    status = (f"{check.n} checks, {check.n_eq} printed values against the paper and {check.n - check.n_eq} consistency "
              f"checks on the files, {len(check.mismatches)} mismatches")
    doc = [
        "# SPILLWAY benchmark tables",
        "",
        "Generated by `benchmarks/scripts/make_tables.py` from `benchmarks/results/*.json` (the per-cell results "
        "released with the paper). Every printed value is read or computed from those files and compared with the paper's "
        "printed numbers, except that ROPE's two ChatInject composites use the benign utility the paper prints. "
        f"Result: {status}.",
        "",
        "Conventions: BU = benign utility, UAU = utility under attack, ASR = in-scope attack success (executed "
        "effect, content-manipulation tasks dropped), NRP = BU x (1 - ASR), printed NRP (BU) in Table 2 beside "
        "NRP (UAU) = UAU x (1 - ASR), ERS = harmonic mean of (1 - ASR) and BU. "
        "Higher is better except ASR. ASR .000 means no in-scope hit on these AgentDojo cells; the guarantee is "
        "scoped to identity targets, a spoofed typed field is out of scope.",
        "",
    ]
    for i, (title, caption, table) in enumerate(sections, 1):
        doc += [f"## {i}. {title}", "", caption, "", table, ""]
    doc += ["## Data notes", ""]
    if notes:
        doc += ["Notes on individual cells:", ""] + [f"- {n}" for n in notes] + [""]
    else:
        doc += ["No cell needs a note.", ""]
    return "\n".join(doc), check


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--results", type=Path, default=RESULTS_DIR, help="directory with the result JSON files")
    parser.add_argument(
        "--out", type=Path, default=OUT_FILE, help="markdown file to write (default benchmarks/TABLES.md)"
    )
    parser.add_argument("--no-write", action="store_true", help="print and check only")
    parser.add_argument("--quiet", action="store_true", help="do not print the tables")
    args = parser.parse_args(argv)
    doc, check = build(args.results)
    if not args.quiet:
        print(doc)
    for line in doc.split("## Data notes", 1)[-1].splitlines():
        if line.startswith("- "):
            print("make_tables.py: data note: " + line[2:], file=sys.stderr)
    if check.mismatches:
        print(f"make_tables.py: {len(check.mismatches)} of {check.n} values differ from the paper:", file=sys.stderr)
        for line in check.mismatches:
            print("  " + line, file=sys.stderr)
        return 1
    if not args.no_write:
        args.out.write_text(doc, encoding="utf-8")
        print(f"make_tables.py: {check.n} checks pass; wrote {args.out}", file=sys.stderr)
    else:
        print(f"make_tables.py: {check.n} checks pass", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
