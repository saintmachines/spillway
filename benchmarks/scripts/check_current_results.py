#!/usr/bin/env python3
"""Compare generated site numbers with the independently extracted paper snapshot.

Standard library only. Reads the supplied artifacts; writes only an explicitly
requested --report. This checks numerical display consistency, not browser
appearance, benchmark execution, runtime equivalence, or bibliography numbering.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
from fractions import Fraction
from pathlib import Path


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def text(fragment: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]*>", " ", fragment))).strip()


def parse_tables(source: str) -> list[list[list[str]]]:
    return [
        [
            [text(c) for c in re.findall(r"<t[hd]\b[^>]*>(.*?)</t[hd]>", row, re.S)]
            for row in re.findall(r"<tr\b[^>]*>.*?</tr>", table, re.S)
        ]
        for table in re.findall(r"<table\b[^>]*>.*?</table>", source, re.S)
    ]


def audit(baseline_path: Path, output: Path) -> dict:
    canonical = json.loads(baseline_path.read_text())
    # Derive the SPILLWAY means from integer-count records independently of
    # the display builder, including the two different averaging units.
    standard = [r["methods"]["SPILLWAY"] for r in canonical["table1"]["rows"]]
    summary = canonical["table2"]["printed_rows"]["SPILLWAY"]
    for count_key, metric in (("BU_count", "BU"), ("UAU_count", "UAU")):
        mean = sum(Fraction(r[count_key]) for r in standard) / 12
        assert f"{float(mean):.3f}" == f"{summary[metric]:.3f}", metric
    pis = canonical["final_PISmith_receipt"]
    for numerator, metric in (("utility_hits", "UAU"), ("in_scope_hits", "ASR")):
        mean = sum(Fraction(r[numerator], r["N"]) for r in pis["per_suite_counts"]) / 4
        assert abs(float(mean) - pis[metric + "_macro"]) < 1e-12, metric
    dyn = canonical["AgentDyn_receipt"]
    bars = {r["suite"].lower(): r["SPILLWAY"]["UAU"]["exact_value"] for r in canonical["figure4"]["bars"]}
    for row in dyn["native_suite_means"]:
        mean = Fraction(row["R1_hits"] + row["R2_hits"] + row["R0R_hits"], 3 * row["per_repeat_UIDs"])
        assert abs(float(mean) - bars[row["suite"]]) < 1e-12, row["suite"]
    result_path = output / "results.json"
    html_path = output / "results.html"
    data = json.loads(result_path.read_text())
    tables = parse_tables(html_path.read_text())
    counts = {"JSON_numeric_checks": 0, "HTML_numeric_checks": 0}
    issues: list[dict] = []

    def compare(actual, expected, location: str, *, rendered: bool = False) -> None:
        counts["HTML_numeric_checks" if rendered else "JSON_numeric_checks"] += 1
        same = actual == expected if rendered else abs(actual - expected) <= 1e-12
        if not same:
            issues.append({"at": location, "got": actual, "expected": expected})

    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    methods = list(canonical["table2"]["printed_rows"])
    backbones = {r["backbone"] for r in canonical["table1"]["rows"]}
    require(len(data["cells"]) == len(canonical["table1"]["rows"]) == 12,
            "Expected all twelve standard cells")
    for row, expected in zip(data["cells"], canonical["table1"]["rows"]):
        require((row["suite"], row["backbone"]) == (expected["suite"], expected["backbone"]),
                "Cell identity/order mismatch")
        require(set(row["methods"]) == set(methods), "Standard method inventory mismatch")
        for method, values in row["methods"].items():
            for metric in ("BU", "UAU", "ASR"):
                expected_values = expected["methods"][method]
                target = expected_values.get("exact_" + metric, expected_values[metric]) \
                    if method == "SPILLWAY" else expected_values[metric]
                compare(values[metric.lower()], target,
                        f"cells/{row['suite']}/{row['backbone']}/{method}/{metric}")

    summary_mapping = {
        "bu": "BU", "uau": "UAU", "asr_in_scope": "ASR", "nrp_bu": "NRP_BU",
        "nrp_uau": "NRP_UAU", "ers": "ERS", "cells_leaking_of_12": "in_scope_leak_cells",
    }
    require(set(data["grid_means"]) == set(methods), "Summary method inventory mismatch")
    for method, values in data["grid_means"].items():
        for actual_key, expected_key in summary_mapping.items():
            compare(values[actual_key], canonical["table2"]["printed_rows"][method][expected_key],
                    f"grid/{method}/{actual_key}")

    require(set(data["stress"]["rows"]) == set(methods), "Stress method inventory mismatch")
    for method, rows in data["stress"]["rows"].items():
        source = canonical["table4"]["printed_rows"][method]
        pairs = [source[group][suite] for group, suite in (
            ("ChatInject", "Workspace"), ("ChatInject", "Slack"),
            ("AutoDojo", "Banking"), ("AutoDojo", "Slack"), ("AutoDojo", "Travel"),
        )] + [source["PISmith"]]
        require(len(rows) == len(pairs) == 6, "Stress condition inventory mismatch")
        for index, (actual, expected) in enumerate(zip(rows, pairs)):
            for actual_key, metric in (("uau", "UAU"), ("asr_in_scope", "ASR")):
                target = canonical["final_PISmith_receipt"][metric + "_macro"] \
                    if method == "SPILLWAY" and index == 5 else expected[metric]
                compare(actual[actual_key], target, f"stress/{method}/{index}/{metric}")

    routing = data["delegated_routing_vs_rope"]
    require(len(routing) == len(canonical["figure4"]["bars"]) == 7,
            "Expected all seven routing suites")
    for actual, expected in zip(routing, canonical["figure4"]["bars"]):
        require(actual["suite"] == expected["suite"], "Routing suite identity/order mismatch")
        for actual_key, method, metric in (
            ("spillway_uau", "SPILLWAY", "UAU"), ("spillway_asr", "SPILLWAY", "ASR"),
            ("rope_uau", "ROPE (Opus 4.8 router)", "UAU"),
            ("rope_asr", "ROPE (Opus 4.8 router)", "ASR"),
        ):
            compare(actual[actual_key], expected[method][metric]["exact_value"],
                    f"routing/{actual['suite']}/{actual_key}")
        for actual_key, metric in (("rope_gpt_4o_mini_router_uau", "UAU"),
                                   ("rope_gpt_4o_mini_router_asr", "ASR")):
            target = canonical["table7"]["printed_rows"][actual["suite"]][
                "ROPE (gpt-4o-mini router)"][metric]
            compare(actual[actual_key], target, f"own_router/{actual['suite']}/{metric}")

    figure_points = data["standard_attack_gpt_4o_mini_suite_means_figure_1a"]
    require(set(figure_points) == set(methods), "Figure1a method inventory mismatch")
    for method, values in figure_points.items():
        for actual_key, metric in (("uau", "UAU"), ("asr_in_scope", "ASR")):
            compare(values[actual_key], canonical["figure1"]["points"]["standard"][method][metric],
                    f"fig1a/{method}/{metric}")

    # Identify rendered tables by their headers and row shapes, not table order.
    def find_table(predicate, name: str):
        found = [table for table in tables if predicate(table)]
        require(len(found) == 1, f"Expected one rendered {name} table; found {len(found)}")
        return found[0]

    summary = find_table(lambda t: any("NRP (BU)" in c for r in t[:2] for c in r)
                         and any("Cells leaking" in c for c in t[0]), "summary")
    standard = find_table(lambda t: sum(len(r) == 17 and any(b in r[0] for b in backbones)
                                       for r in t) == 12, "standard utility/ASR")
    benign = find_table(lambda t: sum(len(r) == 9 and any(b in r[0] for b in backbones)
                                     for r in t) == 12, "benign utility")
    stress = find_table(lambda t: any("ChatInject" in c for c in t[0])
                        and any("PISmith" in c for c in t[0]), "stress")
    routing_table = find_table(lambda t: any("ROPE, Claude Opus 4.8 router" in c
                                            for c in t[0]), "routing")

    def fmt(value) -> str:
        return f"{value:.3f}".replace("0.", ".").replace("-0.", "-.")

    summary_rows = [r for r in summary if r[0] in methods]
    require(len(summary_rows) == 8, "Incomplete rendered summary methods")
    for row in summary_rows:
        require(len(row) == 8, "Unexpected rendered summary columns")
        for actual, metric in zip(row[1:], ("BU", "UAU", "ASR", "NRP_BU", "NRP_UAU",
                                            "ERS", "in_scope_leak_cells")):
            target = canonical["table2"]["printed_rows"][row[0]][metric]
            expected = str(int(target)) if metric == "in_scope_leak_cells" else fmt(target)
            compare(actual, expected, f"HTML summary/{row[0]}/{metric}", rendered=True)
    standard_rows = [r for r in standard if len(r) == 17 and any(b in r[0] for b in backbones)]
    benign_rows = [r for r in benign if len(r) == 9 and any(b in r[0] for b in backbones)]
    for index, expected in enumerate(canonical["table1"]["rows"]):
        require(expected["suite"] in standard_rows[index][0]
                and expected["backbone"] in standard_rows[index][0],
                "Rendered standard row identity/order mismatch")
        require(expected["suite"] in benign_rows[index][0]
                and expected["backbone"] in benign_rows[index][0],
                "Rendered benign row identity/order mismatch")
        for method_index, method in enumerate(methods):
            for metric_index, metric in enumerate(("UAU", "ASR")):
                compare(standard_rows[index][1 + 2 * method_index + metric_index],
                        fmt(expected["methods"][method][metric]),
                        f"HTML standard/{index}/{method}/{metric}", rendered=True)
            compare(benign_rows[index][1 + method_index], fmt(expected["methods"][method]["BU"]),
                    f"HTML benign/{index}/{method}", rendered=True)
    stress_count = 0
    for row in stress:
        method = row[0].rstrip("‡†").strip()
        if method not in methods:
            continue
        stress_count += 1
        require(len(row) == 13, "Unexpected rendered stress columns")
        for index, expected in enumerate(data["stress"]["rows"][method]):
            for metric_index, metric in enumerate(("uau", "asr_in_scope")):
                compare(row[1 + 2 * index + metric_index], fmt(expected[metric]),
                        f"HTML stress/{method}/{index}/{metric}", rendered=True)
    require(stress_count == 8, "Incomplete rendered stress methods")
    routing_count = 0
    for row in routing_table:
        if row[0] not in canonical["table7"]["printed_rows"] or len(row) != 7:
            continue
        routing_count += 1
        for method_index, method in enumerate(("SPILLWAY", "ROPE (Opus 4.8 router)",
                                                "ROPE (gpt-4o-mini router)")):
            for metric_index, metric in enumerate(("UAU", "ASR")):
                target = canonical["table7"]["printed_rows"][row[0]][method][metric]
                compare(row[1 + 2 * method_index + metric_index], fmt(target),
                        f"HTML routing/{row[0]}/{method}/{metric}", rendered=True)
    require(routing_count == 7, "Incomplete rendered routing suite rows")
    return {
        "status": "PASS" if not issues else "FAIL",
        **counts,
        "issues": issues,
        "artifacts": {"baseline": {"path": str(baseline_path), "sha256": sha(baseline_path)},
                      "results_json": {"path": str(result_path), "sha256": sha(result_path)},
                      "results_html": {"path": str(html_path), "sha256": sha(html_path)}},
        "scope": "Final-paper snapshot versus generated JSON and rendered HTML table text; no benchmark rerun or browser visual audit",
        "side_effects": "Read-only except the explicitly requested report file",
    }


def main() -> int:
    here = Path(__file__).resolve().parent
    root = here.parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=root / "benchmarks/results/evaluation_20261118.json")
    parser.add_argument("--output-dir", type=Path, default=root / "docs",
                        help="Directory containing results.json and results.html")
    parser.add_argument("--report", type=Path, help="Optional report path; no write otherwise")
    args = parser.parse_args()
    try:
        report = audit(args.baseline.resolve(), args.output_dir.resolve())
    except (AssertionError, KeyError, OSError, TypeError, ValueError, IndexError) as exc:
        report = {"status": "FAIL", "error": f"{type(exc).__name__}: {exc}"}
    serialized = json.dumps(report, indent=2) + "\n"
    if args.report:
        args.report.write_text(serialized)
    print(serialized, end="")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
