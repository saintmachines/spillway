#!/usr/bin/env python3
"""Run the release checks that the project page reports and save what they print to docs/_build/checks.txt.

build_page.py reads that file: the page shows the first two commands and their output verbatim, and its check
table takes the counts from them. All three checks are offline (no server, no model call). Run it with the
interpreter of an environment that has the dev and agentdojo extras (pip install -e ".[dev,agentdojo]"), so the
three differential tests run instead of being skipped.

usage: python docs/_build/capture_checks.py
"""
import datetime
import pathlib
import platform
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CHECKS = [
    ("python benchmarks/scripts/make_tables.py --no-write --quiet 2>&1 | tail -1",
     [sys.executable, "benchmarks/scripts/make_tables.py", "--no-write", "--quiet"], True),
    ("python -m pytest -q tests | tail -1",
     [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"], True),
    ("python -m spillway_guard.agentdojo.runner --self-test",
     [sys.executable, "-W", "ignore::RuntimeWarning", "-m", "spillway_guard.agentdojo.runner", "--self-test"], False),
]


def main():
    sys.path.insert(0, str(ROOT / "src"))
    import spillway_guard
    out = [f"# captured {datetime.date.today().isoformat()} with spillway-guard {spillway_guard.__version__} on Python {platform.python_version()}"]
    for shown, argv, last_line_only in CHECKS:
        p = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True)
        text = (p.stdout + p.stderr).strip().splitlines()
        if p.returncode != 0:
            sys.exit(f"capture_checks.py: `{shown}` exited {p.returncode}:\n" + "\n".join(text))
        out += [f"$ {shown}"] + (text[-1:] if last_line_only else text)
    path = ROOT / "docs" / "_build" / "checks.txt"
    path.write_text("\n".join(out) + "\n")
    print(path.read_text(), end="")


if __name__ == "__main__":
    main()
