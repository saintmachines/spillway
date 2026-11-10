"""Caller-level checks: an explicit option must reach the actual gate aliases."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import _path  # noqa: F401

from spillway_guard.agentdojo import runner


class TargetRecoveryRunnerTests(unittest.TestCase):
    def prepare_in_environment(self, values, arguments):
        with tempfile.TemporaryDirectory() as directory:
            reference = Path(directory)
            (reference / "harness").mkdir()
            (reference / "spillway_gate.py").write_text(
                'import os\na = os.environ.get("SPW_ESCALATE_MV")\n'
                'b = os.environ.get("OLD_MV_INTEGRITY")\n'
            )
            (reference / "harness" / "gate.py").write_text(
                'import os\na = os.environ.get("OLD_ESCALATE_MV")\n'
                'b = os.environ.get("OLD_MV_INTEGRITY")\n'
            )
            environment = {"SPW_REFERENCE_DIR": str(reference), **values}
            with patch.dict(os.environ, environment, clear=True), patch.object(
                runner, "install_agent_shim", return_value=False
            ), patch.object(runner.sys, "path", list(runner.sys.path)):
                forwarded, _ = runner.prepare(arguments)
                return forwarded, dict(os.environ)

    def test_explicit_option_disables_stale_and_discovered_target_aliases(self):
        arguments, environment = self.prepare_in_environment(
            {"SPW_ESCALATE_MV": "1", "OLD_ESCALATE_MV": "1"},
            ["--paper", "--no-identity-target-recovery", "--suite", "banking"],
        )
        self.assertNotIn("--no-identity-target-recovery", arguments)
        self.assertNotIn("--paper", arguments)
        self.assertEqual(environment["SPW_ESCALATE_MV"], "0")
        self.assertEqual(environment["OLD_ESCALATE_MV"], "0")
        self.assertEqual(environment["SPW_MV_INTEGRITY"], "1")
        self.assertEqual(environment["OLD_MV_INTEGRITY"], "1")
        for flag in runner.PAPER_FLAGS:
            self.assertEqual(arguments.count(flag), 1)

    def test_explicit_option_preserves_object_recovery_choice(self):
        _, environment = self.prepare_in_environment(
            {"SPW_MV_INTEGRITY": "0", "OLD_MV_INTEGRITY": "0"},
            ["--self-test", "--no-identity-target-recovery"],
        )
        self.assertEqual(environment["SPW_ESCALATE_MV"], "0")
        self.assertEqual(environment["SPW_MV_INTEGRITY"], "0")
        self.assertEqual(environment["OLD_MV_INTEGRITY"], "0")

    def test_default_paper_configuration_is_preserved(self):
        _, environment = self.prepare_in_environment({}, ["--paper", "--self-test"])
        self.assertEqual(environment["SPW_ESCALATE_MV"], "1")
        self.assertEqual(environment["OLD_ESCALATE_MV"], "1")
        self.assertEqual(environment["SPW_MV_INTEGRITY"], "1")

    def test_ordinary_run_defaults_target_recovery_off_even_with_stale_alias(self):
        _, environment = self.prepare_in_environment(
            {"OLD_ESCALATE_MV": "1"}, ["--auto", "--self-test"]
        )
        self.assertEqual(environment["SPW_ESCALATE_MV"], "0")
        self.assertEqual(environment["OLD_ESCALATE_MV"], "0")
        self.assertEqual(environment["SPW_MV_INTEGRITY"], "1")

    def test_explicit_target_recovery_opt_in_is_preserved(self):
        _, environment = self.prepare_in_environment(
            {"SPW_ESCALATE_MV": "1"}, ["--auto", "--self-test"]
        )
        self.assertEqual(environment["SPW_ESCALATE_MV"], "1")
        self.assertEqual(environment["OLD_ESCALATE_MV"], "1")

    def test_payload_no_escalate_is_forwarded_as_a_distinct_option(self):
        arguments, environment = self.prepare_in_environment(
            {}, ["--paper", "--no-escalate", "--self-test"]
        )
        self.assertIn("--no-escalate", arguments)
        self.assertEqual(environment["SPW_ESCALATE_MV"], "1")
