# Per-cell results

These files hold the per-cell results behind Tables 1 to 3, Appendix Table 5 without its ROPE column, Appendix Table
8, Figure 4, Figure 3's Slack and Workspace values, and six of the eight rows of Table 4's ChatInject panel.
`benchmarks/scripts/make_tables.py` writes [`../TABLES.md`](../TABLES.md) from them and runs 590 checks against the
paper and the files. [`pismith_a4/`](pismith_a4/) holds the PISmith reports behind Appendix Table 7.

These files are per-cell aggregates. Per-pair logs are not released, so the means and the tables can be recomputed
from them, and a cell's hit count cannot be rechecked from a trace. A row with `scored` 0 is an unfilled slot and holds
no result.

One cell has two attack-success counts. For the undefended agent on qwen3:8b Slack, `breadth_grid_cells.json` counts
48 hits of 105 (.457) and `breadth_grid_summary.json` counts 47 (.448). AgentDojo's check counts one
`injection_task_5` pair in this cell from the transcript, but its effect did not execute. The paper counts a hit only
when the environment changed and applies ROPE's rescoring to every method, which removes this hit. The paper's tables
print .448, and `make asr-levels` subtracts the same hit.
