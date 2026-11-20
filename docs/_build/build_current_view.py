#!/usr/bin/env python3
"""Render the existing site with the final 18 November evaluation snapshot.

The historical builders and their original inputs remain reproducible. This
display layer changes no SDK defaults, benchmark logs or published wheel.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import re
import sys
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SNAPSHOT = ROOT / "benchmarks/results/evaluation_20261118.json"
SOURCE_LABEL = "Latest benchmark evaluation · 18 Nov 2026"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load():
    spec = importlib.util.spec_from_file_location("spillway_release014_display", HERE / "build_release014_view.py")
    view = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = view
    spec.loader.exec_module(view)
    module = view.load_historical()
    original_json = module.results_json
    report = view.activate(module, json.loads(view.ACTUAL.read_text()))
    return module, original_json, report


def activate(module, data):
    old_cells = copy.deepcopy(module.CELLS)
    old_data = copy.deepcopy(module.DATA)
    rows = data["table1"]["rows"]
    assert len(rows) == 12
    module.CELLS = []
    for row in rows:
        methods = {}
        for method, values in row["methods"].items():
            methods[method] = {name.lower(): values[name] for name in ("BU", "UAU", "ASR")}
            if method == "SPILLWAY":
                methods[method]["bu"] = values["exact_BU"]
                methods[method]["uau"] = values["exact_UAU"]
        module.CELLS.append({"suite": row["suite"], "backbone": row["backbone"], "methods": methods})
    module.DATA["grid"] = {
        method: tuple(row[k] for k in ("BU", "UAU", "ASR", "NRP_BU", "ERS")) + (int(row["in_scope_leak_cells"]),)
        for method, row in data["table2"]["printed_rows"].items()
    }
    module.DATA["nrp_uau"] = {m: row["NRP_UAU"] for m, row in data["table2"]["printed_rows"].items()}
    module.DATA["stress"] = {}
    for method, row in data["table4"]["printed_rows"].items():
        pairs = [tuple(row[group][suite][k] for k in ("UAU", "ASR")) for group, suite in (
            ("ChatInject", "Workspace"), ("ChatInject", "Slack"), ("AutoDojo", "Banking"),
            ("AutoDojo", "Slack"), ("AutoDojo", "Travel"))]
        module.DATA["stress"][method] = pairs + [tuple(row["PISmith"][k] for k in ("UAU", "ASR"))]
    pis = data["final_PISmith_receipt"]
    module.DATA["stress"]["SPILLWAY"][5] = (pis["UAU_macro"], pis["ASR_macro"])
    module.PIS_SUITES["SPILLWAY"] = {
        row["suite"].capitalize(): (Fraction(row["utility_hits"], row["N"]), Fraction(row["in_scope_hits"], row["N"]))
        for row in pis["per_suite_counts"]
    }
    figure_bars = data["figure4"]["bars"]
    module.DATA["rope"] = [
        (row["suite"], *[row[method][key]["exact_value"] for method, key in (
            ("SPILLWAY", "UAU"), ("SPILLWAY", "ASR"), ("ROPE (Opus 4.8 router)", "UAU"), ("ROPE (Opus 4.8 router)", "ASR"))])
        for row in figure_bars
    ]
    mean = data["table7"]["printed_rows"]["Mean"]
    module.DATA["rope_mean"] = (mean["SPILLWAY"]["UAU"], mean["SPILLWAY"]["ASR"],
                                mean["ROPE (Opus 4.8 router)"]["UAU"], mean["ROPE (Opus 4.8 router)"]["ASR"])
    own = "ROPE (gpt-4o-mini router)"
    module.ROPE_AGENT_ROUTER_ROWS = [(s, data["table7"]["printed_rows"][s][own]["UAU"],
                                    data["table7"]["printed_rows"][s][own]["ASR"])
                                   for s in module.AGENTDOJO_SUITES + module.AGENTDYN_SUITES]
    module.DATA["fig4a"] = {
        method: tuple(values[k] for k in ("UAU", "ASR"))
        for method, values in data["figure1"]["points"]["standard"].items()
    }
    dojo_rope = [r for r in figure_bars if r["suite"] in module.AGENTDOJO_SUITES]
    module.DATA["fig4a"]["ROPE"] = tuple(sum(r["ROPE (Opus 4.8 router)"][k]["exact_value"] for r in dojo_rope) / 4 for k in ("UAU", "ASR"))
    original_points = module.fig4_points

    def points(cols):
        values = original_points(cols)
        key = {(0, 1): "ChatInject", (2, 3, 4): "AutoDojo", (5,): "PISmith"}.get(tuple(cols) if cols else ())
        if key:
            point = data["figure1"]["points"][key]["SPILLWAY"]
            values["SPILLWAY"] = (point["UAU"], point["ASR"])
        return values

    module.fig4_points = points
    module.UAU_NEXT_M = "DRIFT"
    module.UAU_NEXT = module.DATA["grid"]["DRIFT"][1]
    module.STRESS_MAX = pis["ASR_macro"]
    module.STRESS_MAX_COL = "PISmith"
    module.FIG1_META = "AgentDojo standard attack · four-suite mean · " + SOURCE_LABEL
    module.FIG4_GRID_META = "Suite means · " + SOURCE_LABEL
    module.FIG4_GRID_TITLE = "SPILLWAY combines the lowest mean attack success with high utility."
    module.FIG4_GRID_NOTE = (
        "SPILLWAY has zero attack success in (a) to (c). In (d), its suite-mean ASR is .006 at .263 utility, "
        "against ROPE's .007 at .173 utility. AutoDojo's 389 released pairs include four rule-development examples; "
        "held-out Banking sets have .014 and .000 executed attack success."
    )
    # Keep original peer cells and the earlier cost/component cohorts intact.
    for old, current in zip(old_cells, module.CELLS):
        assert (old["suite"], old["backbone"]) == (current["suite"], current["backbone"])
        for method in module.METHODS:
            if method != "SPILLWAY":
                assert old["methods"][method] == current["methods"][method]
    assert module.DATA["calls"] == old_data["calls"] and module.DATA["seconds"] == old_data["seconds"]
    for row in module.CELLS:
        for key in ("bu", "uau", "asr"):
            assert 0 <= row["methods"]["SPILLWAY"][key] <= 1


def refresh_copy(text):
    media = json.loads((ROOT / "docs/assets/CURRENT_MEDIA.json").read_text())
    for item in media["files"]:
        public_path = item["public_path"].removeprefix("docs/")
        text = re.sub(re.escape(public_path) + r"(?:\?v=[0-9a-f]+)?",
                      public_path + "?v=" + item["sha256"][:8], text)
    replacements = {
        '<a href="release-1.0.1-scope.md">1.0.1 SDK scope</a>': '<a href="https://github.com/saintmachines/spillway/blob/main/docs/release-1.0.1-scope.md">1.0.1 SDK scope</a>',
        "SPILLWAY: Real-time safety guard for AI agents. 48.9% task success under standard attack and 0/2847 in-scope attack successes, judge on. At most 500 ms added per task on average in the paper timing study.": "SPILLWAY: Real-time safety guard for AI agents. 47.4% task success under standard attack and 0/2847 in-scope attack successes, judge on. At most 500 ms added per task on average in the paper timing study.",
        "SPILLWAY 1.0.0 / comparison methods: paper": SOURCE_LABEL,
        "Tables 4 and 7": "Table 4",
        "Table 8": "Table 7",
        "SPILLWAY: 1.0.0; comparison methods and reruns: the paper": "Latest standard-attack evaluation; repeat study: earlier paper configuration",
        "SPILLWAY: 1.0.0; comparison methods: the paper. Temperature 0, seed 42": "Latest standard-attack evaluation. Temperature 0, seed 42",
        "SPILLWAY 1.0.0 has no executed attack effect": "SPILLWAY has no executed in-scope attack effect",
        "SPILLWAY 1.0.0 uses the matched backbone and task/scoring protocol; comparison methods retain the paper measurements.": "All methods use the matched backbone and scoring protocol.",
        "SPILLWAY 1.0.0, four mini suites": "Latest SPILLWAY evaluation, four mini suites",
        "Watch SPILLWAY 1.0.0": "Watch SPILLWAY",
        "On gpt&#8209;4o&#8209;mini under the standard attack, the current four AgentDojo rows and historical three AgentDyn rows have no in&#8209;scope leak and more utility than the paper's ROPE results with its authors' Claude Opus 4.8 router.": "On gpt&#8209;4o&#8209;mini under the standard attack, SPILLWAY has no in&#8209;scope leak and higher utility on every AgentDojo and AgentDyn suite than ROPE with its authors' Claude Opus 4.8 router.",
        "SPILLWAY's four AgentDojo rows use the current measurements; the three AgentDyn rows and ROPE retain the paper measurements. The seven-suite mean combines those two sources.": "SPILLWAY averages .612 utility on AgentDojo and .448 on AgentDyn, against ROPE's .530 and .385. AgentDyn uses the trusted native integration and averages three repeats with agent seed 42.",
        "SPILLWAY has macro ASR @@STRESS_MAX@@ under PISmith on mini, with utility .257 and 4/949 effects. The qwen3:8b run has 1/949 effects.": "SPILLWAY has suite-mean ASR @@STRESS_MAX@@ under PISmith on mini, at .263 utility.",
        "SPILLWAY has macro ASR .006 under PISmith on mini, with utility .257 and 4/949 effects. The qwen3:8b run has 1/949 effects.": "SPILLWAY has suite-mean ASR .006 under PISmith on mini, at .263 utility.",
        "SPILLWAY 1.0.0: four AgentDojo suites; AgentDyn and ROPE: paper. The unweighted seven-suite mean combines current and historical rows": "Latest evaluation: four AgentDojo suites and three AgentDyn suites. AgentDyn: trusted native integration, three fixed-seed repeats; mean unweighted over suites",
        "SPILLWAY 1.0.0 values are shown in the standard and stress charts and four AgentDojo routing rows. AgentDyn, ablation and cost comparisons retain their paper measurements.": "Charts show the latest standard-attack, stress-test and delegated-routing results. Cost and component studies use their recorded earlier configurations.",
        "The 1.0.0 standard attack uses AgentDojo v1.2.2 on three backbones, one run per cell. The paper also reports 27 reruns over three seeds and AgentDyn on gpt-4o-mini, one run per suite.": "The standard attack uses AgentDojo v1.2.2 on three backbones, one run per cell. AgentDyn uses the trusted native integration and three fixed-seed repeats. The earlier repeat study reports 27 runs over three seeds.",
        "PISmith mini .257 utility / .005 ASR (4/949), qwen3:8b .173 / .002 (1/949)": "PISmith on gpt-4o-mini: .263 utility / .006 suite-mean ASR",
        "The same validated runtime was measured in 0.1.4; these are SPILLWAY 1.0.0 results.": "Tables reproduce the latest full-system evaluation snapshot.",
        "Runtime equivalence and measurement provenance": "Earlier runtime-equivalence record",
        "Current SPILLWAY 1.0.0 rows and plots are built from the final measurements by <code>docs/_build/build_release014_view.py</code>.": "Current rows and plots are built from the final evaluation snapshot by <code>docs/_build/build_current_view.py</code>.",
        "SPILLWAY 1.0.0 standard, stress and four AgentDojo routing rows come from": "The latest standard, stress and delegated-routing rows come from",
        "; comparison methods, AgentDyn, cost and ablations retain paper values.": ". Cost and component studies retain their recorded earlier configurations.",
        "SPILLWAY's AgentDojo rows are current; its three AgentDyn rows and all ROPE rows are historical. The mean combines current and historical rows.": "AgentDyn uses the trusted native integration and averages three fixed-seed repeats. The mean is unweighted over the seven suites.",
        "/blob/main/benchmarks/results/release_014_actual.json": "/blob/main/benchmarks/results/evaluation_20261118.json",
        "/blob/main/docs/_build/build_release014_view.py": "/blob/main/docs/_build/build_current_view.py",
        'The historical paper ablation (Table 3) disables recovery of refused identity targets while keeping fixed delegation rules and the object judge enabled. The qwen3:8b cells have zero attack success, at mean utility .354 instead of .370.': 'In the recorded component study, disabling identity-target recovery while retaining delegation rules and the object judge gives zero attack success at mean utility .354 on qwen3:8b. The final full-system row in Table 3 uses Table 1 measurements and reaches .359 utility at zero attack success.',
        'In the historical size ablation, a 4-bit gemma4:12b also kept zero attack success on the qwen3:8b cells and the ChatInject panel, at utility .348 instead of .370.': 'In the recorded size ablation, a 4-bit gemma4:12b also kept zero attack success on the qwen3:8b cells and the ChatInject panel, at utility .348.',
        'Four current AgentDojo + three historical AgentDyn suites': 'Latest evaluation · four AgentDojo + three AgentDyn suites',
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    text = re.sub(r'<figure class="rt" id="campaign">.*?</figure>',
                  '<figure class="rt" id="campaign"><figcaption class="cap"><span class="tn">Evaluation snapshot</span>'
                  '<h2>Measurements and configurations</h2></figcaption><p class="tnote">The full configuration enables the local judge '
                  'and identity-target recovery. Default library use leaves both off. AgentDyn adds the trusted native-application contracts '
                  'and averages three repeats with agent seed 42. '
                  '<a href="https://github.com/saintmachines/spillway/blob/main/benchmarks/results/evaluation_20261118.json">'
                  'Tables, integer-count receipts and scope</a>.</p></figure>', text, flags=re.S)
    return text


def refresh_home_descriptions(page, data):
    counts = [
        tuple(map(int, row["methods"]["SPILLWAY"]["ASR_count"].split("/")))
        for row in data["table1"]["rows"]
    ]
    hits = sum(hit_count for hit_count, _ in counts)
    pairs = sum(pair_count for _, pair_count in counts)
    utility = data["public_headlines"]["standard_12cell_means"]["UAU"]
    result, replaced = re.subn(
        r'<meta (?:name="description"|property="og:description") content="[^"]*48\.9%[^"]*0/2847[^"]*">',
        lambda match: match[0].replace("48.9%", f"{utility:.1%}").replace("0/2847", f"{hits}/{pairs}"),
        page,
    )
    if replaced != 2:
        raise ValueError("Expected the project home page description and Open Graph description")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "docs/index.html")
    args = parser.parse_args()
    data = json.loads(SNAPSHOT.read_text())
    module, original_json, historical = load()
    activate(module, data)
    # Update text before placeholder substitution; update generated table copy too.
    module.TEMPLATE = refresh_copy(module.TEMPLATE)
    module.RESULTS_TEMPLATE = refresh_copy(module.RESULTS_TEMPLATE)
    page = refresh_copy(module.build())
    results = json.loads(original_json())
    results["source"] = SOURCE_LABEL
    results["evaluation_snapshot"] = "benchmarks/results/evaluation_20261118.json"
    results["evaluation_snapshot_sha256"] = sha(SNAPSHOT)
    results["display_view"] = {"date": "2026-11-18", "library_version": module.project_version(),
                               "configuration": "local judge and identity-target recovery enabled",
                               "agentdyn": "same core guard, explicit trusted native integration, three fixed-seed repeats"}
    results["notes"]["grid_means"] = "Final printed twelve-cell means; equal weight over three backbones and four suites."
    results["notes"]["standard_attack_gpt_4o_mini_suite_means_figure_1a"] = "Latest four-suite mean; ROPE uses its authors' Opus 4.8 router."
    results["notes"]["delegated_routing_vs_rope"] = "Latest recorded evaluation; AgentDyn uses the trusted native integration and three fixed-seed repeats."
    results["notes"]["pismith_gpt_4o_mini_by_suite"] = "SPILLWAY uses the final independently checked selected-949 records. Other methods retain their recorded comparison values."
    results["notes"]["stress"] = "ChatInject: qwen3:8b. AutoDojo and PISmith: gpt-4o-mini; PISmith open-loop ASR@1, mean over four suites. AutoDojo includes four rule-development examples; held-out Banking executed ASR .014 and .000."
    results["notes"]["cost_and_ablation"] = "Table 3 full-system row: final Table 1 qwen3:8b values; component-only rows: recorded component-study configurations. Timing values retain their earlier configurations and separate-session episode-time means."
    results["component_study_qwen3_8b"] = copy.deepcopy(data["table3"])
    out = args.out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    outputs = {
        "index.html": refresh_home_descriptions(page, data),
        "results.html": refresh_copy(module.build_results_page(page)),
        "integrate.html": refresh_copy(module.build_integration_page(page)),
        "results.json": json.dumps(results, indent=1) + "\n",
    }
    for name, value in outputs.items():
        (out if name == "index.html" else out.parent / name).write_text(value)
    report = {"status": "CURRENT_EVALUATION_DISPLAY_BUILD_PASS", "snapshot_sha256": sha(SNAPSHOT),
              "historical_checks": historical["historical_checks"], "standard_cells": len(module.CELLS),
              "grid_spillway": results["grid_means"]["SPILLWAY"], "routing_mean": module.DATA["rope_mean"],
              "benchmark_runs": 0, "runtime_changes": False,
              "output_sha256": {name: sha(out if name == "index.html" else out.parent / name) for name in outputs}}
    (out.parent / "CURRENT_EVALUATION_RECEIPT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
