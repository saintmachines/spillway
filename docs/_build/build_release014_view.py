#!/usr/bin/env python3
"""Build the original site design with actual 0.1.4 display values.

The unchanged historical builder is imported and all its paper assertions run
FIRST. Only private in-memory copies are then changed. No cached experiment,
historical source, SDK member, wheel or default builder is modified.

Usage: PYTHONPATH=src python docs/_build/build_release014_view.py [--out DIR/index.html]
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from fractions import Fraction

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = HERE / "build_page.py"
ACTUAL = ROOT / "benchmarks/results/release_014_actual.json"
CAPTION = "SPILLWAY 0.1.4 / comparison methods: paper"
EXPECTED_ACTUAL_SHA256 = "5b62ac9ca06495e5155df85122abf871cdfc3e8f12a8c3308951999ec3f70bfd"
MODEL = {"gpt-4o-mini-2024-07-18": "gpt-4o-mini", "qwen3-coder:30b": "qwen3-coder:30b", "qwen3:8b": "qwen3:8b"}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_historical():
    spec = importlib.util.spec_from_file_location("spillway_historical_page_builder", SOURCE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    assert module.MT_N == 590 and not module._check.mismatches
    assert module.DATA["grid"]["SPILLWAY"] == (.520, .484, .000, .520, .684, 0)
    assert module.DATA["fig4a"]["SPILLWAY"] == (.614, .000)
    return module


def ratio(row):
    denominator = row["denominator"]
    assert isinstance(denominator, int) and denominator > 0
    assert 0 <= row["utility_hits"] <= denominator
    utility = row["utility_hits"] / denominator
    if "original_reported_asr_numerator" not in row:
        return utility, None
    n, d = row["original_reported_asr_numerator"], row["original_reported_asr_denominator"]
    assert isinstance(n, int) and isinstance(d, int) and d > 0 and 0 <= n <= d
    return utility, n / d


def activate(module, actual):
    """Apply one explicit display view after the original frozen checks pass."""
    assert actual["version"] == "0.1.4"
    assert actual["measurement_scope_complete"] and actual["source_alignment_review_complete"]
    scope = actual["scope"]
    assert scope["conditions"] == 54 and scope["closed_target_episodes"] == scope["target_episodes"] == 10012
    assert scope["missing_target_UIDs"] == scope["duplicate_target_UIDs"] == 0
    assert actual["wheel_sha256"] == "3f055d6336268ba260b1ae62cad54111ed280738e023253f8ad14e68d8f4f928"
    rows = actual["conditions"]
    assert len(rows) == 54
    index = {(r["group"], r["model"], r["profile"], r["suite"]): r for r in rows}
    assert len(index) == 54, "Duplicate actual condition"
    assert module.DATA["grid"]["SPILLWAY"][1] == .484, "View must start from validated historical data"
    display_version = module.project_version()
    original_data, original_cells = module.DATA, module.CELLS
    module.DATA, module.CELLS = copy.deepcopy(original_data), copy.deepcopy(original_cells)
    module.PIS_SUITES = copy.deepcopy(module.PIS_SUITES)

    standard = {}
    for row in rows:
        if row["group"] in ("standard_attack", "standard_attack_coder", "standard_attack_mini", "standard_benign", "standard_benign_coder", "standard_benign_mini"):
            assert row["model"] in MODEL and row["profile"] == "target_recovery_on"
            kind = "attack" if "attack" in row["group"] else "benign"
            key = (MODEL[row["model"]], row["suite"].capitalize(), kind)
            assert key not in standard
            standard[key] = row
    assert len(standard) == 24
    for cell in module.CELLS:
        key = (cell["backbone"], cell["suite"])
        bu, _ = ratio(standard[(*key, "benign")])
        uau, asr = ratio(standard[(*key, "attack")])
        cell["methods"]["SPILLWAY"] = {"bu": bu, "uau": uau, "asr": asr}
    macro = actual["standard_macro12"]
    for column, name in (("bu", "BU"), ("uau", "UAU"), ("asr", "ASR")):
        mean = sum(c["methods"]["SPILLWAY"][column] for c in module.CELLS) / 12
        assert abs(mean - float(macro[name])) <= .0006, (column, mean, macro[name])
    module.DATA["grid"]["SPILLWAY"] = tuple(float(macro[k]) for k in ("BU", "UAU", "ASR", "NRP_BU", "ERS_BU")) + (0,)
    module.DATA["nrp_uau"]["SPILLWAY"] = float(macro["NRP_UAU"])
    mini = actual["standard_per_model_macro4"]["gpt-4o-mini-2024-07-18"]
    mini_cells = [c["methods"]["SPILLWAY"] for c in module.CELLS if c["backbone"] == "gpt-4o-mini"]
    assert len(mini_cells) == 4
    assert abs(sum(c["uau"] for c in mini_cells) / 4 - float(mini["UAU"])) <= .0006
    module.DATA["fig4a"]["SPILLWAY"] = (float(mini["UAU"]), float(mini["ASR"]))

    def select(group, suite):
        matches = [r for r in rows if r["group"] == group and r["suite"] == suite]
        assert len(matches) == 1, (group, suite)
        return matches[0]

    ci = [ratio(select("chatinject", s)) for s in ("workspace", "slack")]
    auto = [ratio(select("autodojo", s)) for s in ("banking", "slack", "travel")]
    pis = {s: ratio(select("pismith_mini", s.lower())) for s in module.AGENTDOJO_SUITES}
    pis_macro = actual["stress_macro_and_pooled_separate"]["pismith_mini"]
    for i, key in ((0, "UAU_suite_macro"), (1, "ASR_suite_macro")):
        assert abs(sum(v[i] for v in pis.values()) / 4 - float(pis_macro[key])) <= .0006
    module.DATA["stress"]["SPILLWAY"] = ci + auto + [(float(pis_macro["UAU_suite_macro"]), float(pis_macro["ASR_suite_macro"]))]
    module.PIS_SUITES["SPILLWAY"] = {
        s: (Fraction(select("pismith_mini", s.lower())["utility_hits"], select("pismith_mini", s.lower())["denominator"]),
            Fraction(select("pismith_mini", s.lower())["original_reported_asr_numerator"], select("pismith_mini", s.lower())["original_reported_asr_denominator"]))
        for s in module.AGENTDOJO_SUITES
    }
    all_asr = [a for _, a in module.DATA["stress"]["SPILLWAY"]]
    module.STRESS_MAX = max(all_asr)
    module.STRESS_MAX_COL = module.DATA["stress_cols"][all_asr.index(module.STRESS_MAX)].split(" · ")[0]
    defenses = sorted((m for m in module.DATA["grid"] if m != "Undefended"), key=lambda m: -module.DATA["grid"][m][1])
    module.UAU_NEXT_M, module.UAU_NEXT = defenses[1], module.DATA["grid"][defenses[1]][1]
    module.FIG1_META = "AgentDojo standard attack · four-suite mean · " + CAPTION
    module.FIG4_GRID_META = "Suite means · " + CAPTION
    module.FIG4_GRID_NOTE = ("SPILLWAY keeps the most utility in (a) and (c). In (b) and (d) DRIFT keeps more utility and has higher attack success. "
                             "PISmith on mini: 4/949 effects, macro ASR .005 and utility .257. On qwen3:8b: 1/949 effects, macro ASR .002 and utility .173.")

    # Edit measured source captions in memory. Original source/template files remain frozen.
    module.TEMPLATE = module.TEMPLATE.replace(
        "SPILLWAY lets no injected effect execute in 2,847 attacked pairs, in scope or not, and has no in&#8209;scope leak in 27 reruns over three seeds. Source: Tables 1 and 2 and Appendix B of the preprint",
        "SPILLWAY 0.1.4 has no executed attack effect in 2,847 standard-attack pairs. The paper also reports no in&#8209;scope leak in 27 reruns over three seeds. SPILLWAY: 0.1.4; comparison methods and reruns: the paper",
    )
    module.TEMPLATE = module.TEMPLATE.replace(
        "Source: Tables 1 and 2 of the preprint, temperature 0, seed 42",
        "SPILLWAY: 0.1.4; comparison methods: the paper. Temperature 0, seed 42",
    )
    module.TEMPLATE = module.TEMPLATE.replace(
        "AgentDojo v1.2.2 on three backbones, one run per cell, plus 27 reruns over three seeds. AgentDyn on gpt-4o-mini, one run per suite.",
        "The 0.1.4 standard attack uses AgentDojo v1.2.2 on three backbones, one run per cell. The paper also reports 27 reruns over three seeds and AgentDyn on gpt-4o-mini, one run per suite.",
    )
    module.TEMPLATE = module.TEMPLATE.replace("SPILLWAY ties ROPE at @@STRESS_MAX@@ under PISmith, with more utility.",
                                              "SPILLWAY has macro ASR @@STRESS_MAX@@ under PISmith on mini, with utility .257 and 4/949 effects. The qwen3:8b run has 1/949 effects.")
    module.TEMPLATE = module.TEMPLATE.replace("Detailed results · AgentDyn and stress tests", "Stress tests and the paper's seven-suite comparison")
    module.TEMPLATE = module.TEMPLATE.replace("SPILLWAY has zero in&#8209;scope attack success on all seven suites, one run each on gpt&#8209;4o&#8209;mini.",
                                              "The paper's seven-suite comparison and the stronger attacks.")
    module.TEMPLATE = module.TEMPLATE.replace("The seven suites are AgentDojo's four and AgentDyn's three, one run each on gpt&#8209;4o&#8209;mini.",
                                              "The paper's seven-suite comparison uses AgentDojo's four and AgentDyn's three, one run each on gpt&#8209;4o&#8209;mini.")
    module.TEMPLATE = module.TEMPLATE.replace("Source: Tables 4 and 7 of the preprint", CAPTION + "; PISmith mini .257 utility / .005 ASR (4/949), qwen3:8b .173 / .002 (1/949)")
    module.TEMPLATE = module.TEMPLATE.replace("The charts report their recorded paper configurations.",
                                              "SPILLWAY values in the standard and stress charts are from 0.1.4. Seven-suite, ablation and cost comparisons retain their paper measurements.")
    if display_version == "1.0.0":
        module.TEMPLATE = module.TEMPLATE.replace("Version 0.1.4 uses the enhanced default", "Version @@PACKAGE_VERSION@@ uses the enhanced default")
        module.TEMPLATE = re.sub(
            r'(<p class="req">Default:.*?</p>)',
            r'\1<p class="req inote">The same validated runtime was measured in 0.1.4. <a href="release-1.0.0.html#runtime-equivalence">Runtime equivalence</a>.</p>',
            module.TEMPLATE, count=1, flags=re.S,
        )
        # Until root supplies a verified 1.0.0 film, keep the existing clip explicitly
        # identified as recorded 0.1.4 footage, rather than silently renaming it.
        if "assets/SPILLWAY_100_Final_28s_1080p.mp4" not in module.TEMPLATE:
            module.TEMPLATE = module.TEMPLATE.replace("Watch the 28-second overview", "Watch the recorded 0.1.4 overview")
    module.TEMPLATE = module.TEMPLATE.replace("Every method uses the same agent and scorer.",
                                              "SPILLWAY 0.1.4 uses the matched backbone and task/scoring protocol; comparison methods retain the paper measurements.")
    # Existing cost/ablation/seven-suite arrays intentionally stay untouched.
    module.TEMPLATE = module.TEMPLATE.replace('<h3 id="rope-cap">', '<h3 id="rope-cap">Paper comparison: ')
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace("Full results · from the preprint", CAPTION)
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace("Preprint Table 2", CAPTION).replace("Preprint Table 1", CAPTION)
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace("Preprint Figure 1a, values", "Mini standard attack · " + CAPTION)
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace("Preprint Tables 4 and 7", "Stress tests · " + CAPTION)
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace("Preprint Table 8", "Paper seven-suite comparison · Table 8")
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace(
        "The script <code>benchmarks/scripts/make_tables.py</code> regenerates Tables 1 to 3, the ChatInject columns, Table 8 and the cost values from those files.",
        "The paper's comparison records are checked by <code>benchmarks/scripts/make_tables.py</code>. Current SPILLWAY rows and plots are built from the final 0.1.4 measurements by <code>docs/_build/build_release014_view.py</code>.",
    )
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace("The AutoDojo and PISmith columns are copied from Tables 4 and 7 of the preprint.",
        'SPILLWAY standard and stress values come from <a href="' + module.REPO + '/blob/main/benchmarks/results/release_014_actual.json">the actual 0.1.4 report</a>; comparison methods, cost, ablations and the seven-suite table retain paper values.')
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace("SPILLWAY's AutoDojo row uses the address and payee-change rules, written on its four failing pairs. Held-out Banking sets give",
        "In the paper's earlier AutoDojo audit, address and payee-change rules were written on four failing pairs. Those paper held-out Banking sets give")

    original_strip = module.results_strip
    module.results_strip = lambda: original_strip().replace("as in Table 2 of the preprint.", "SPILLWAY 0.1.4 / comparison methods: paper.")
    original_fig_table = module.table_fig4a
    def fig_table():
        value = original_fig_table()
        return re.sub(r'(<tr class="us">.*?<td class="txt">).*?(</td></tr>)', r'\g<1>SPILLWAY 0.1.4, four mini suites\2', value, count=1, flags=re.S)
    module.table_fig4a = fig_table
    original_json = module.results_json
    def rendered_json():
        result = json.loads(original_json())
        result["source"] = CAPTION
        result["display_view"] = {"version": "0.1.4", "measurement_version": "0.1.4", "display_version": display_version,
                                  "library_version": display_version, "runtime_equivalence_url": "release-1.0.0.html#runtime-equivalence" if display_version == "1.0.0" else None,
                                  "actual_source": "benchmarks/results/release_014_actual.json", "scope": "standard and stress SPILLWAY slots", "paper_only": ["other methods", "seven-suite routing", "ablation", "cost and latency"]}
        result["notes"]["grid_means"] = "SPILLWAY 0.1.4 / comparison methods: paper; equal-weight twelve-cell means."
        result["notes"]["standard_attack_gpt_4o_mini_suite_means_figure_1a"] = "Four mini suites; SPILLWAY 0.1.4, other points paper; ROPE uses its authors' router."
        result["notes"]["stress"] = "SPILLWAY actual 0.1.4 / comparison methods: paper. ChatInject: qwen3:8b; AutoDojo/PISmith: mini; first PISmith variant, ASR@1."
        result["additional_actual_stress"] = actual["stress_macro_and_pooled_separate"]
        return json.dumps(result, indent=1)
    module.results_json = rendered_json
    assert module.DATA["calls"] == original_data["calls"] and module.DATA["seconds"] == original_data["seconds"]
    assert module.DATA["rope"] == original_data["rope"] and module.DATA["rope_mean"] == original_data["rope_mean"]
    for method in original_data["grid"]:
        if method != "SPILLWAY":
            assert module.DATA["grid"][method] == original_data["grid"][method]
    for before, after in zip(original_cells, module.CELLS):
        assert all(before["methods"][m] == after["methods"][m] for m in module.METHODS if m != "SPILLWAY")
    return {"historical_checks": module.MT_N, "conditions": 54, "standard_cells": 12, "mini_scatter": module.DATA["fig4a"]["SPILLWAY"],
            "main_macro12": macro, "cache_files_modified": False, "paper_cost_ablation_seven_suite_preserved": True,
            "chatinject_hits": [select("chatinject", s)["utility_hits"] for s in ("workspace", "slack")],
            "autodojo_hits": sum(select("autodojo", s)["utility_hits"] for s in ("banking", "slack", "travel"))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "docs/index.html")
    parser.add_argument("--actual-json", type=Path, default=ACTUAL)
    args = parser.parse_args()
    assert sha(args.actual_json) == EXPECTED_ACTUAL_SHA256, "Not the reviewed actual 0.1.4 source JSON"
    protected = [SOURCE, HERE / "cells_table1.json"] + [
        p for p in (ROOT / "benchmarks").rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and p.suffix not in (".pyc", ".pyo")
    ]
    before = {str(p.relative_to(ROOT)): sha(p) for p in protected}
    module = load_historical()
    report = activate(module, json.loads(args.actual_json.read_text()))
    page = module.build()
    out = args.out.resolve();out.parent.mkdir(parents=True, exist_ok=True)
    outputs = {"index.html": page, "results.html": module.build_results_page(page), "integrate.html": module.build_integration_page(page), "results.json": module.results_json()}
    for name, value in outputs.items():
        target = out if name == "index.html" else out.parent / name
        target.write_text(value)
    assert before == {str(p.relative_to(ROOT)): sha(p) for p in protected}, "Historical source/cache changed"
    report.update(status="ACTUAL014_DISPLAY_ONLY_BUILD_PASS", actual_json_sha256=sha(args.actual_json), historical_inputs_sha256=before,
                  output_sha256={name: sha(out if name == "index.html" else out.parent / name) for name in outputs},
                  display_version=module.project_version(), library_version=module.project_version(), measurement_version="0.1.4")
    (out.parent / "RELEASE014_DISPLAY_RECEIPT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k not in ("historical_inputs_sha256", "output_sha256")}))


if __name__ == "__main__":
    main()
