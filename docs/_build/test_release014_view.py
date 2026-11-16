"""CPU-only source/display regression checks. No model, browser or network."""
import copy
from fractions import Fraction
import importlib.util
import json
from pathlib import Path
import re
import sys
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "src"))
spec = importlib.util.spec_from_file_location("release014_view_tested", HERE / "build_release014_view.py")
view = importlib.util.module_from_spec(spec)
spec.loader.exec_module(view)
ACTUAL = json.loads(view.ACTUAL.read_text())


class ActualDisplayView(unittest.TestCase):
    def setUp(self):
        self.m = view.load_historical()
        self.old_data = copy.deepcopy(self.m.DATA)
        self.old_cells = copy.deepcopy(self.m.CELLS)

    def apply(self, data=None):
        return view.activate(self.m, copy.deepcopy(ACTUAL if data is None else data))

    def test_default_historical_builder_still_checks_590_and_old_points(self):
        self.assertEqual(self.m.MT_N, 590)
        self.assertEqual(self.m.DATA["fig4a"]["SPILLWAY"], (.614, 0))
        page = self.m.build()
        self.assertIn('data-v="0.6140,0.0000"', page)

    def test_exact_actual_source_hash(self):
        self.assertEqual(view.sha(view.ACTUAL), view.EXPECTED_ACTUAL_SHA256)

    def test_macro12_values_and_mini_point_have_distinct_denominators(self):
        self.apply()
        self.assertEqual(self.m.DATA["grid"]["SPILLWAY"], (.539, .489, 0, .539, .700, 0))
        self.assertEqual(self.m.DATA["nrp_uau"]["SPILLWAY"], .489)
        self.assertEqual(self.m.DATA["fig4a"]["SPILLWAY"], (12263/20160, 0))
        self.assertNotEqual(self.m.DATA["grid"]["SPILLWAY"][1], 1533 / 2847)

    def test_actual_cell_joins_use_model_suite_not_storage_order(self):
        data = copy.deepcopy(ACTUAL);data["conditions"].reverse()
        self.apply(data)
        banking = next(c for c in self.m.CELLS if c["suite"] == "Banking" and c["backbone"] == "gpt-4o-mini")
        workspace = next(c for c in self.m.CELLS if c["suite"] == "Workspace" and c["backbone"] == "gpt-4o-mini")
        self.assertEqual(banking["methods"]["SPILLWAY"], dict(bu=9/16, uau=64/144, asr=0))
        self.assertEqual(workspace["methods"]["SPILLWAY"], dict(bu=33/40, uau=475/560, asr=0))

    def test_all_peers_in_all_twelve_cells_stay_unchanged(self):
        self.apply()
        for before, after in zip(self.old_cells, self.m.CELLS):
            for method in self.m.METHODS:
                if method != "SPILLWAY":
                    self.assertEqual(before["methods"][method], after["methods"][method])

    def test_all_seven_peer_hero_points_stay_unchanged(self):
        self.apply()
        for method in self.old_data["fig4a"]:
            if method != "SPILLWAY":
                self.assertEqual(self.m.DATA["fig4a"][method], self.old_data["fig4a"][method])

    def test_chat_and_auto_use_full_actual_counts(self):
        result = self.apply()
        self.assertEqual(result["chatinject_hits"], [222, 30])
        self.assertEqual(result["autodojo_hits"], 205)
        self.assertEqual(self.m.DATA["stress"]["SPILLWAY"][:2], [(222/560,0), (30/105,0)])
        self.assertEqual(self.m.DATA["stress"]["SPILLWAY"][2:5], [(69/144,0),(59/105,0),(77/140,0)])

    def test_pis_nonzero_and_exact_per_suite_fraction_preserved(self):
        self.apply()
        self.assertAlmostEqual(self.m.DATA["stress"]["SPILLWAY"][-1][0], 5177/20160)
        self.assertAlmostEqual(self.m.DATA["stress"]["SPILLWAY"][-1][1], 17/3360)
        rows = [r for r in ACTUAL["conditions"] if r["group"] == "pismith_mini"]
        self.assertEqual(sum(r["original_reported_asr_numerator"] for r in rows), 4)
        for r in rows:
            self.assertEqual(self.m.PIS_SUITES["SPILLWAY"][r["suite"].capitalize()][1], Fraction(r["original_reported_asr_numerator"], r["original_reported_asr_denominator"]))

    def test_geometry_and_tooltips_follow_actual_points(self):
        self.apply()
        hero = self.m.fig_hero()
        self.assertIn('data-v="0.6083,0.0000"', hero)
        self.assertNotIn('data-v="0.6140,0.0000"', hero)
        self.assertIn("Banking utility .444", hero)
        self.assertIn("Workspace utility .848", hero)
        x = self.m.f4_x(12263/20160, self.m.FIG1_X)
        self.assertIn(f'--x: {x:.4f}', hero)
        bars = self.m.why_charts()[0]
        self.assertIn('style="--f: 0.9780"', bars)

    def test_all_four_pages_render_with_actual_tables_and_nonzero_pis(self):
        self.apply()
        page = self.m.build()
        results = self.m.build_results_page(page)
        integration = self.m.build_integration_page(page)
        data = json.loads(self.m.results_json())
        self.assertIn('data-v="0.2568,0.0051"', page)
        self.assertIn("1/949 effects", page)
        self.assertNotIn("SPILLWAY ties ROPE at", page)
        self.assertNotIn("SPILLWAY 0.1.4", page)
        self.assertNotIn("SPILLWAY 0.1.4", results)
        self.assertNotIn("0.1.4", page)
        self.assertEqual(results.count("0.1.4"), 1)
        self.assertIn('<td>.539</td><td>.489</td><td>.000</td>', results)
        self.assertIn("SPILLWAY 1.0.0, four mini suites", results)
        self.assertIn("<html", integration)
        self.assertEqual(data["grid_means"]["SPILLWAY"]["uau"], .489)
        self.assertEqual(data["standard_attack_gpt_4o_mini_suite_means_figure_1a"]["SPILLWAY"]["uau"], 12263/20160)

    def test_paper_cost_ablation_agentdyn_and_all_rope_values_remain_paper(self):
        old_nojudge, old_judge = self.m.NO_JUDGE[:], self.m.WITH_JUDGE[:]
        self.apply()
        for key in ("calls", "seconds", "judge_calls"):
            self.assertEqual(self.m.DATA[key], self.old_data[key])
        self.assertEqual((self.m.NO_JUDGE, self.m.WITH_JUDGE), (old_nojudge, old_judge))
        self.assertEqual(self.m.DATA["rope"][4:], self.old_data["rope"][4:])
        self.assertEqual([r[3:] for r in self.m.DATA["rope"]], [r[3:] for r in self.old_data["rope"]])
        self.assertIn("three AgentDyn rows and ROPE retain the paper measurements", self.m.TEMPLATE)

    def test_four_scatter_points_are_exact_macros_and_peers_are_unchanged(self):
        before = {key: copy.deepcopy(self.m.fig4_points(cols)) for key, _, cols, *_ in self.m.FIG4}
        self.apply()
        expected = {"a": (12263/20160, 0), "b": (191/560, 0),
                    "c": (297/560, 0), "d": (5177/20160, 17/3360)}
        for key, _, cols, *_ in self.m.FIG4:
            after = self.m.fig4_points(cols)
            for method in after:
                if method == "SPILLWAY":
                    for i in (0, 1):
                        self.assertAlmostEqual(after[method][i], expected[key][i], places=15)
                else:
                    self.assertEqual(after[method], before[key][method])

    def test_routing_agentdojo_rows_and_mixed_mean_follow_current_counts(self):
        report = self.apply()
        self.assertEqual([r[1] for r in self.m.DATA["rope"][:4]], [64/144, 59/105, 81/140, 475/560])
        self.assertEqual(report["routing_mixed_mean"], 97057/176400)
        self.assertEqual(f'{report["routing_mixed_ers_uau"]:.3f}', '0.699')
        table = self.m.table_rope()
        for value in (".444", ".562", ".579", ".848", ".550"):
            self.assertIn(value, table)
        data = json.loads(self.m.results_json())
        self.assertEqual([r["spillway_measurement"] for r in data["delegated_routing_vs_rope"]],
                         ["current"]*4 + ["historical_agentdyn_not_rerun"]*3)

    def test_all_54_conditions_have_distinct_profile_bound_rows(self):
        self.apply()
        data = json.loads(self.m.results_json())
        self.assertEqual(len(data["current_conditions"]), 54)
        self.assertEqual(sum(r["denominator"] for r in data["current_conditions"]), 10012)
        self.assertEqual(len({(r["group"], r["model"], r["suite"], r["profile"]) for r in data["current_conditions"]}), 54)
        results = self.m.build_results_page(self.m.build())
        self.assertIn("All 54 SPILLWAY conditions", results)
        self.assertIn("Default library use enables neither", results)

    def test_pis_value_labels_do_not_move_points(self):
        self.apply()
        panel = self.m.fig4_mini(*self.m.FIG4[-1])
        self.assertEqual(panel.count('class="pis-value '), 2)
        self.assertIn("ASR .005", panel)
        self.assertIn("ASR .007", panel)
        self.assertIn('data-v="0.2568,0.0051"', panel)
        self.assertIn('data-v="0.1730,0.0070"', panel)
        self.assertNotIn("A tied defense", self.m.FIG4_GRID_TITLE)
        for args in self.m.FIG4[:3]:
            standard = self.m.fig4_mini(*args)
            self.assertEqual(standard.count('class="pis-value '), 1)
            self.assertIn("ASR .000", standard)

    def test_current_recompute_link_and_historical_cost_link_are_distinct(self):
        self.apply()
        page = self.m.build()
        standard = page.split('id="c-util"', 1)[1].split('</figure>', 1)[0]
        cost = page.split('id="c-time"', 1)[1].split('</figure>', 1)[0]
        self.assertIn('/docs/_build/build_release014_view.py', standard)
        self.assertNotIn('/benchmarks/scripts/make_tables.py', standard)
        self.assertIn('/benchmarks/scripts/make_tables.py', cost)

    def test_display_version_does_not_rename_measurement_identity(self):
        self.apply()
        data = json.loads(self.m.results_json())
        self.assertEqual(data["display_view"]["library_version"], "1.0.0")
        self.assertEqual(data["display_view"]["version"], "1.0.0")
        self.assertEqual(data["display_view"]["display_version"], "1.0.0")
        self.assertEqual(data["display_view"]["measurement_version"], "0.1.4")
        self.assertEqual(ACTUAL["version"], "0.1.4")
        self.assertEqual(ACTUAL["wheel_sha256"], "3f055d6336268ba260b1ae62cad54111ed280738e023253f8ad14e68d8f4f928")

    def test_install_controls_follow_verified_registry_state(self):
        self.apply()
        page = self.m.build()
        publication = json.loads(self.m.PUBLICATION_PATH.read_text())
        if publication["pypi_version"] is None:
            self.assertIn("pip install git+https://github.com/saintmachines/spillway.git@release/1.0.0", page)
            self.assertIn("Available after the PyPI release", page)
        else:
            self.assertEqual(publication["pypi_version"], "1.0.0")
            self.assertIn('id="cmd-install">pip install spillway-guard==1.0.0', page)

    def test_browser_demo_wheel_is_present_and_matches_its_loader(self):
        filename = "spillway_guard-1.0.0-py3-none-any.whl"
        expected = "38ab16762fa4ba7d1f943265a10da28619e94afa2ca3fddd46c11be7535b5a76"
        wheel = ROOT / "docs" / "wheels" / filename
        self.assertTrue(wheel.is_file(), "The deployed browser demo needs its frozen wheel")
        self.assertEqual(view.sha(wheel), expected)
        loader = (ROOT / "docs" / "try.html").read_text()
        self.assertIn("wheels/" + filename, loader)
        self.assertIn(expected, loader)

    def test_historical_files_and_source_data_objects_remain_unchanged(self):
        paths = [view.SOURCE, HERE/"cells_table1.json", view.ACTUAL]
        before = {str(p):view.sha(p) for p in paths}
        original = self.m.DATA
        self.apply();self.m.build()
        self.assertEqual(original, self.old_data)
        self.assertEqual(before, {str(p):view.sha(p) for p in paths})

    def test_partial_campaign_refused(self):
        data=copy.deepcopy(ACTUAL);data["scope"]["closed_target_episodes"]=10011
        with self.assertRaises(AssertionError):self.apply(data)

    def test_wrong_macro_cannot_override_underlying_counts(self):
        data=copy.deepcopy(ACTUAL);data["standard_macro12"]["UAU"]=".900"
        with self.assertRaises(AssertionError):self.apply(data)

    def test_duplicate_condition_refused(self):
        data=copy.deepcopy(ACTUAL);data["conditions"][-1]=copy.deepcopy(data["conditions"][0])
        with self.assertRaises(AssertionError):self.apply(data)

    def test_wrong_snapshot_or_missing_standard_cell_refused(self):
        data=copy.deepcopy(ACTUAL)
        next(r for r in data["conditions"] if r["group"]=="standard_attack_mini")["model"]="gpt-4o-mini"
        with self.assertRaises(AssertionError):self.apply(data)

    def test_wrong_wheel_refused(self):
        data=copy.deepcopy(ACTUAL);data["wheel_sha256"]="0"*64
        with self.assertRaises(AssertionError):self.apply(data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
