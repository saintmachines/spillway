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
CAPTION = "SPILLWAY 1.0.0 / comparison methods: paper"
EXPECTED_ACTUAL_SHA256 = "5b62ac9ca06495e5155df85122abf871cdfc3e8f12a8c3308951999ec3f70bfd"
HISTORICAL_ROUTING = ROOT / "benchmarks/results/delegated_routing_opus_router.json"
HISTORICAL_ROUTING_SHA256 = "fe153d4097afc7116e7ead9d865792cef219de6d36f11706bc7e06b6c510c0fa"
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


def condition_table(module, rows):
    """Expose every measured condition without merging macro and pooled views."""
    body = []
    for row in rows:
        utility, asr = ratio(row)
        hits = "—" if asr is None else f'{row["original_reported_asr_numerator"]}/{row["original_reported_asr_denominator"]}'
        body.append(
            '<tr>' + ''.join(f'<td>{module.esc(str(v))}</td>' for v in (
                row["group"], row["model"], row["suite"], row["profile"],
                f'{row["utility_hits"]}/{row["denominator"]}', module.d3(utility),
                hits, "—" if asr is None else module.d3(asr),
            )) + '</tr>'
        )
    return ('<table class="data wide"><thead><tr>'
            '<th>Condition</th><th>Model</th><th>Suite</th><th>Recovery profile</th>'
            '<th>Utility hits / attempts</th><th>Utility</th><th>Effects / ASR denominator</th><th>ASR</th>'
            '</tr></thead><tbody>' + ''.join(body) + '</tbody></table>')


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
    # Plot exact count-derived means; three-decimal strings are display labels.
    module.DATA["fig4a"]["SPILLWAY"] = tuple(sum(c[k] for c in mini_cells) / 4 for k in ("uau", "asr"))

    # Figure 4 / delegated routing reuses the same four mini standard cells.
    # AgentDyn and both ROPE router configurations were not rerun.
    mini_by_suite = {c["suite"]: c["methods"]["SPILLWAY"] for c in module.CELLS if c["backbone"] == "gpt-4o-mini"}
    module.DATA["rope"] = [
        (s, mini_by_suite[s]["uau"], mini_by_suite[s]["asr"], ru, ra)
        if s in mini_by_suite else (s, su, sa, ru, ra)
        for s, su, sa, ru, ra in original_data["rope"]
    ]
    # The three historical count ratios are from the released AgentDyn records.
    # Keep their original plotted precision (.600/.435/.383) above.
    assert sha(HISTORICAL_ROUTING) == HISTORICAL_ROUTING_SHA256
    routing_records = json.loads(HISTORICAL_ROUTING.read_text())["scores"]
    dyn_records = [routing_records["spw_full_s42_" + s.lower()] for s in module.AGENTDYN_SUITES]
    assert all(r["complete"] and r["reportable"] and r["scored"] == r["grid"] and r["inscope_hits"] == 0 for r in dyn_records)
    historical_dyn = tuple(Fraction(r["utility_hits"], r["grid"]) for r in dyn_records)
    assert [module.d3(u) for u in historical_dyn] == [module.d3(r[1]) for r in original_data["rope"][4:]]
    mixed_uau = (sum(Fraction(standard[("gpt-4o-mini", s, "attack")]["utility_hits"],
                              standard[("gpt-4o-mini", s, "attack")]["denominator"])
                     for s in module.AGENTDOJO_SUITES) + sum(historical_dyn)) / 7
    mixed_ers = sum(2 * u / (1 + u) for u in [
        *(Fraction(standard[("gpt-4o-mini", s, "attack")]["utility_hits"],
                    standard[("gpt-4o-mini", s, "attack")]["denominator"])
          for s in module.AGENTDOJO_SUITES), *historical_dyn,
    ]) / 7
    module.DATA["rope_mean"] = (float(mixed_uau), 0, *original_data["rope_mean"][2:])

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
    module.DATA["stress"]["SPILLWAY"] = ci + auto + [tuple(sum(v[i] for v in pis.values()) / 4 for i in (0, 1))]
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
    module.FIG4_GRID_TITLE = "In all four attacks, SPILLWAY has the lowest attack success at three decimals."
    module.FIG4_GRID_NOTE = ("SPILLWAY keeps the most utility in (a) and (c). In (b) and (d) DRIFT keeps more utility and has higher attack success. "
                             "PISmith on mini: 4/949 effects, macro ASR .005 and utility .257. On qwen3:8b: 1/949 effects, macro ASR .002 and utility .173.")

    # Direct labels show SPILLWAY's ASR in every panel and distinguish PISmith's
    # two low-ASR points without moving marks, axes or scales.
    original_mini = module.fig4_mini
    def annotated_mini(key, tab, cols, xr, top, xt, rope_ring):
        result = original_mini(key, tab, cols, xr, top, xt, rope_ring)
        labels = []
        points = module.fig4_points(cols)
        low = module.F4_LOW_BY.get(key, module.F4_LOW)
        specs = (("ROPE", 3, -20), ("SPILLWAY", 12, 0)) if key == "d" else (("SPILLWAY", -12, 0),)
        for method, dx, dy in specs:
            u, a = points[method]
            align = "0px" if key == "d" else "-100%"
            labels.append(
                f'<span class="pis-value m-{module.FIG4_MARK[method][0]}" '
                f'style="--x: {module.f4_x(u, xr):.4f}; --y: {module.f4_y(a, top, low):.4f}; '
                f'--dx: {dx}px; --dy: {dy}px; --align: {align}">ASR {module.d3(a)}</span>'
            )
        return result.replace("</div>", "".join(labels) + "</div>", 1)
    module.fig4_mini = annotated_mini
    module.TEMPLATE = module.TEMPLATE.replace("</style>",
        '.pis-value{position:absolute;left:calc(100% * var(--x));bottom:calc(100% * var(--y));'
        'transform:translate(calc(var(--align) + var(--dx)),calc(50% + var(--dy)));font:500 .6875rem/1 var(--mono);'
        'color:var(--m);background:var(--wash-card,var(--surface));padding:2px;'
        'white-space:nowrap;pointer-events:none;z-index:8}'
        '.db-kt .k.rope{transform:translateX(-4px)}.db-kt .k.hi{transform:translateX(4px)}'
        '</style>', 1)

    # Edit measured source captions in memory. Original source/template files remain frozen.
    module.TEMPLATE = module.TEMPLATE.replace(
        "SPILLWAY lets no injected effect execute in 2,847 attacked pairs, in scope or not, and has no in&#8209;scope leak in 27 reruns over three seeds. Source: Tables 1 and 2 and Appendix B of the preprint",
        "SPILLWAY 1.0.0 has no executed attack effect in 2,847 standard-attack pairs. The paper also reports no in&#8209;scope leak in 27 reruns over three seeds. SPILLWAY: 1.0.0; comparison methods and reruns: the paper",
    )
    module.TEMPLATE = module.TEMPLATE.replace(
        "Source: Tables 1 and 2 of the preprint, temperature 0, seed 42",
        "SPILLWAY: 1.0.0; comparison methods: the paper. Temperature 0, seed 42",
    )
    module.TEMPLATE = module.TEMPLATE.replace(
        'href="@@REPO@@/blob/main/benchmarks/scripts/make_tables.py#@@MT_SUMMARY_L@@"',
        'href="@@REPO@@/blob/main/docs/_build/build_release014_view.py" data-historical-table-line="@@MT_SUMMARY_L@@"',
    )
    module.TEMPLATE = module.TEMPLATE.replace(
        '<a href="@@REPO@@/tree/main/benchmarks/results">Per-cell records on GitHub</a>',
        '<a href="@@REPO@@/blob/main/benchmarks/results/release_014_actual.json">Current SPILLWAY condition counts</a>',
    )
    module.TEMPLATE = module.TEMPLATE.replace(
        "AgentDojo v1.2.2 on three backbones, one run per cell, plus 27 reruns over three seeds. AgentDyn on gpt-4o-mini, one run per suite.",
        "The 1.0.0 standard attack uses AgentDojo v1.2.2 on three backbones, one run per cell. The paper also reports 27 reruns over three seeds and AgentDyn on gpt-4o-mini, one run per suite.",
    )
    module.TEMPLATE = module.TEMPLATE.replace("SPILLWAY ties ROPE at @@STRESS_MAX@@ under PISmith, with more utility.",
                                              "SPILLWAY has macro ASR @@STRESS_MAX@@ under PISmith on mini, with utility .257 and 4/949 effects. The qwen3:8b run has 1/949 effects.")
    module.TEMPLATE = module.TEMPLATE.replace("Detailed results · AgentDyn and stress tests", "Stress tests and the seven-suite comparison")
    module.TEMPLATE = module.TEMPLATE.replace("SPILLWAY has zero in&#8209;scope attack success on all seven suites, one run each on gpt&#8209;4o&#8209;mini.",
                                              "SPILLWAY's seven-suite comparison and the stronger attacks.")
    module.TEMPLATE = module.TEMPLATE.replace("The seven suites are AgentDojo's four and AgentDyn's three, one run each on gpt&#8209;4o&#8209;mini.",
                                              "SPILLWAY's four AgentDojo rows use the current measurements; the three AgentDyn rows and ROPE retain the paper measurements. The seven-suite mean combines those two sources.")
    module.TEMPLATE = module.TEMPLATE.replace("Source: Tables 4 and 7 of the preprint", CAPTION + "; PISmith mini .257 utility / .005 ASR (4/949), qwen3:8b .173 / .002 (1/949)")
    module.TEMPLATE = module.TEMPLATE.replace("The charts report their recorded paper configurations.",
                                              "SPILLWAY 1.0.0 values are shown in the standard and stress charts and four AgentDojo routing rows. AgentDyn, ablation and cost comparisons retain their paper measurements.")
    if display_version == "1.0.0":
        module.TEMPLATE = module.TEMPLATE.replace("Version 0.1.4 uses the enhanced default", "Version @@PACKAGE_VERSION@@ uses the enhanced default")
    module.TEMPLATE = module.TEMPLATE.replace("Every method uses the same agent and scorer.",
                                              "SPILLWAY 1.0.0 uses the matched backbone and task/scoring protocol; comparison methods retain the paper measurements.")
    # Cost/ablation arrays and the three historical AgentDyn rows stay untouched.
    module.TEMPLATE = module.TEMPLATE.replace(
        "Source: Figure 4 and Table 8 of the preprint, one run per suite (seed 42), mean unweighted over suites",
        "SPILLWAY 1.0.0: four AgentDojo suites; AgentDyn and ROPE: paper. The unweighted seven-suite mean combines current and historical rows",
    )
    module.TEMPLATE = module.TEMPLATE.replace(
        "On gpt&#8209;4o&#8209;mini under the standard attack, across AgentDojo's four suites and AgentDyn's three, SPILLWAY has no in&#8209;scope leak and more utility on all seven than ROPE with its authors' Claude Opus 4.8 router.",
        "On gpt&#8209;4o&#8209;mini under the standard attack, the current four AgentDojo rows and historical three AgentDyn rows have no in&#8209;scope leak and more utility than the paper's ROPE results with its authors' Claude Opus 4.8 router.",
    )
    module.TEMPLATE = module.TEMPLATE.replace("fewer added calls, Workspace and Slack", "fewer added calls, historical study")
    module.TEMPLATE = module.TEMPLATE.replace("mean added time per task", "historical mean time gap")
    module.TEMPLATE = module.TEMPLATE.replace('class="tl">fewer added model calls', 'class="tl">fewer model calls (paper)')
    module.TEMPLATE = module.TEMPLATE.replace('class="ts">fewer added calls', 'class="ts">fewer calls (paper)')
    module.TEMPLATE = module.TEMPLATE.replace("Against MELON, Progent and DRIFT, on qwen3:8b benign Workspace and Slack episodes.",
                                              "Historical paper study against MELON, Progent and DRIFT, on qwen3:8b benign Workspace and Slack episodes.")
    module.TEMPLATE = module.TEMPLATE.replace("The paper's Table 3 disables recovery", "The historical paper ablation (Table 3) disables recovery")
    module.TEMPLATE = module.TEMPLATE.replace("The paper uses a 4-bit gemma4:31b on local Ollama. A 4-bit gemma4:12b also kept",
                                              "The recorded full-system profile uses a 4-bit gemma4:31b on local Ollama. In the historical size ablation, a 4-bit gemma4:12b also kept")
    module.TEMPLATE = module.TEMPLATE.replace("Held-out Banking sets give", "Historical held-out Banking sets give")
    module.TEMPLATE = module.TEMPLATE.replace("Interactive · one recorded AgentDojo episode · eight runs", "Interactive · historical recorded AgentDojo episode · eight runs")
    module.TEMPLATE = module.TEMPLATE.replace(
        "is on in these runs (<a href=\"#q-model\">without it</a>).",
        "is on with identity-target recovery in these runs; both are off in a default <code>Guard(task)</code> (<a href=\"#q-model\">without it</a>).",
    )
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace("Full results · from the preprint", CAPTION)
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace("Preprint Table 2", CAPTION).replace("Preprint Table 1", CAPTION)
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace("Preprint Figure 1a, values", "Mini standard attack · " + CAPTION)
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace("Preprint Tables 4 and 7", "Stress tests · " + CAPTION)
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace("Preprint Table 8", "Four current AgentDojo + three historical AgentDyn suites")
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace(
        "The script <code>benchmarks/scripts/make_tables.py</code> regenerates Tables 1 to 3, the ChatInject columns, Table 8 and the cost values from those files.",
        "The paper's comparison records are checked by <code>benchmarks/scripts/make_tables.py</code>. Current SPILLWAY 1.0.0 rows and plots are built from the final measurements by <code>docs/_build/build_release014_view.py</code>.",
    )
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace("The AutoDojo and PISmith columns are copied from Tables 4 and 7 of the preprint.",
        'SPILLWAY 1.0.0 standard, stress and four AgentDojo routing rows come from <a href="' + module.REPO + '/blob/main/benchmarks/results/release_014_actual.json">the actual measurement report</a>; comparison methods, AgentDyn, cost and ablations retain paper values.')
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace("gpt-4o-mini under the standard attack, one run per suite (seed 42). ROPE runs",
        "gpt-4o-mini under the standard attack, seed 42. SPILLWAY's AgentDojo rows are current; its three AgentDyn rows and all ROPE rows are historical. The mean combines current and historical rows. ROPE runs")
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace("Held-out Banking sets give", "Historical held-out Banking sets give")
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace("Preprint Figure 3 (Workspace and Slack), values", "Historical paper Figure 3 (Workspace and Slack), values")
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace(
        '<figure class="rt" id="rope">',
        '<figure class="rt" id="campaign"><figcaption class="cap"><span class="tn">Current measurement report</span>'
        '<h2>All 54 SPILLWAY conditions</h2></figcaption><p class="tnote">10,012 closed target episodes. '
        'Benign rows report task utility; attacked rows retain their original family ASR denominator. '
        'Full-system rows enable the judge and identity-target recovery; explicit recovery-OFF rows are separate. '
        'Default library use enables neither. Suite macros and pooled rates must not be interchanged.</p>'
        '<details class="m"><summary>Condition counts, profiles and rates</summary><div class="scroll">'
        + condition_table(module, rows) + '</div></details></figure><figure class="rt" id="rope">',
        1,
    )
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace(
        '<p class="back-row">',
        '<p class="note">The same validated runtime was measured in 0.1.4; these are SPILLWAY 1.0.0 results. <a href="release-1.0.0.html#runtime-equivalence">Runtime equivalence and measurement provenance</a>.</p><p class="back-row">',
        1,
    )
    module.RESULTS_TEMPLATE = module.RESULTS_TEMPLATE.replace("SPILLWAY's AutoDojo row uses the address and payee-change rules, written on its four failing pairs. Held-out Banking sets give",
        "In the paper's earlier AutoDojo audit, address and payee-change rules were written on four failing pairs. Those paper held-out Banking sets give")

    original_strip = module.results_strip
    module.results_strip = lambda: original_strip().replace("as in Table 2 of the preprint.", "SPILLWAY 1.0.0 / comparison methods: paper.")
    original_fig_table = module.table_fig4a
    def fig_table():
        value = original_fig_table()
        return re.sub(r'(<tr class="us">.*?<td class="txt">).*?(</td></tr>)', r'\g<1>SPILLWAY 1.0.0, four mini suites\2', value, count=1, flags=re.S)
    module.table_fig4a = fig_table
    original_json = module.results_json
    def rendered_json():
        result = json.loads(original_json())
        result["source"] = CAPTION
        result["display_view"] = {"version": display_version, "measurement_version": "0.1.4", "display_version": display_version,
                                  "library_version": display_version, "runtime_equivalence_url": "release-1.0.0.html#runtime-equivalence" if display_version == "1.0.0" else None,
                                  "actual_source": "benchmarks/results/release_014_actual.json", "scope": "standard, stress and four AgentDojo routing SPILLWAY rows", "paper_only": ["other methods", "three AgentDyn routing rows", "ablation", "cost and latency", "27 reruns and held-out studies"]}
        result["notes"]["grid_means"] = "SPILLWAY 1.0.0 / comparison methods: paper; equal-weight twelve-cell means."
        result["notes"]["standard_attack_gpt_4o_mini_suite_means_figure_1a"] = "Four mini suites; SPILLWAY 1.0.0, other points paper; ROPE uses its authors' router."
        result["notes"]["stress"] = "SPILLWAY 1.0.0 / comparison methods: paper. ChatInject: qwen3:8b; AutoDojo/PISmith: mini; first PISmith variant, ASR@1."
        result["notes"]["delegated_routing_vs_rope"] = "SPILLWAY: four current AgentDojo rows and three historical AgentDyn rows; all ROPE rows historical. Seven-suite mean combines current and historical measurements, not a new seven-suite run."
        result["notes"]["pismith_gpt_4o_mini_by_suite"] = "SPILLWAY: current exact condition counts; other methods: historical released paper records."
        result["notes"]["cost_and_ablation"] = "Historical paper measurements; episode-time values are separate-session means, not a new release timing study or individual-episode bound."
        for row in result["delegated_routing_vs_rope"]:
            row["spillway_measurement"] = "current" if row["suite"] in module.AGENTDOJO_SUITES else "historical_agentdyn_not_rerun"
            row["rope_measurement"] = "historical_paper"
        result["delegated_routing_mixed_seven_suite_mean"] = {
            "uau": float(mixed_uau), "asr_in_scope": 0, "nrp_uau": float(mixed_uau),
            "ers_uau_macro_of_per_suite": float(mixed_ers),
            "scope": "four current AgentDojo + three historical AgentDyn suites",
        }
        result["additional_actual_stress"] = actual["stress_macro_and_pooled_separate"]
        result["current_conditions"] = [{k: r[k] for k in (
            "group", "model", "suite", "profile", "denominator", "utility_hits",
            "original_reported_asr_numerator", "original_reported_asr_denominator",
        ) if k in r} for r in rows]
        return json.dumps(result, indent=1)
    module.results_json = rendered_json
    assert module.DATA["calls"] == original_data["calls"] and module.DATA["seconds"] == original_data["seconds"]
    assert module.DATA["rope"][4:] == original_data["rope"][4:]
    assert [r[3:] for r in module.DATA["rope"]] == [r[3:] for r in original_data["rope"]]
    for method in original_data["grid"]:
        if method != "SPILLWAY":
            assert module.DATA["grid"][method] == original_data["grid"][method]
    for before, after in zip(original_cells, module.CELLS):
        assert all(before["methods"][m] == after["methods"][m] for m in module.METHODS if m != "SPILLWAY")
    return {"historical_checks": module.MT_N, "conditions": 54, "standard_cells": 12, "mini_scatter": module.DATA["fig4a"]["SPILLWAY"],
            "main_macro12": macro, "cache_files_modified": False, "paper_cost_ablation_agentdyn_peers_preserved": True,
            "routing_current_suites": list(module.AGENTDOJO_SUITES), "routing_historical_suites": list(module.AGENTDYN_SUITES),
            "routing_mixed_mean": float(mixed_uau), "routing_mixed_ers_uau": float(mixed_ers),
            "historical_agentdyn_source_sha256": HISTORICAL_ROUTING_SHA256,
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
