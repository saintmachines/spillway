# SPILLWAY release: developer targets. `make help` lists them.
PY ?= python3
TABLES := benchmarks/scripts/make_tables.py
ASR_LEVELS := benchmarks/scripts/appendix_asr_levels.py

.PHONY: help install install-agentdojo test tables asr-levels lint selftest cell

help:
	@echo "make install           editable install with the dev extra (pytest, ruff, email-validator)"
	@echo "make install-agentdojo editable install with the dev and agentdojo extras (runs the gate on AgentDojo)"
	@echo "make test              check benchmarks/results against the paper's numbers, then the unit tests"
	@echo "make tables            write benchmarks/TABLES.md from benchmarks/results/*.json"
	@echo "make asr-levels        print Appendix Table 5 (raw / in-scope ASR per cell) from the breadth-grid files, without its ROPE column"
	@echo "make lint              ruff check . (the configuration in ruff.toml, the same as CI)"
	@echo "make selftest          the reference gate's own self-tests (needs the agentdojo extra, no server)"
	@echo "make cell SUITE=banking BACKBONE=qwen3:8b   run one AgentDojo cell with the paper's settings"

# A venv made by `uv venv` ships no pip: run `$(PY) -m ensurepip --upgrade` first, or use `uv pip install -e ".[dev]"`.
install:
	$(PY) -m pip install -e ".[dev]"

install-agentdojo:
	$(PY) -m pip install -e ".[dev,agentdojo]"

# make_tables.py exits non-zero when a printed value differs from the paper, so it is a test.
test:
	$(PY) $(TABLES) --no-write
	@$(PY) -m pytest -q -m "not differential" tests

tables:
	$(PY) $(TABLES) --out benchmarks/TABLES.md

# appendix_asr_levels.py is pinned byte for byte in reference/BUILD_PROVENANCE.md and opens its two input files under
# fixed names in the current directory. This target runs it unchanged in a temporary directory that links the shipped files under
# those names. It reads the per-cell aggregates in those two files, not per-pair records.
asr-levels:
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	ln -s "$(CURDIR)/benchmarks/results/breadth_grid_summary.json" "$$tmp/final_v122.json" && \
	ln -s "$(CURDIR)/benchmarks/results/breadth_grid_cells.json" "$$tmp/tables_v122.json" && \
	$(PY) -c 'import os, runpy, sys; os.chdir(sys.argv[1]); runpy.run_path(sys.argv[2], run_name="__main__")' "$$tmp" "$(CURDIR)/$(ASR_LEVELS)"

lint:
	ruff check .

selftest:
	$(PY) -m spillway_guard.agentdojo.runner --self-test

cell:
	@test -n "$(SUITE)" -a -n "$(BACKBONE)" || { echo "usage: make cell SUITE=<suite> BACKBONE=<model>"; exit 2; }
	bash reproduce/run_cell.sh "$(SUITE)" "$(BACKBONE)"
