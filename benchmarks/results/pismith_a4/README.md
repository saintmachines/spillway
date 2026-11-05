# PISmith on gpt-4o-mini, by suite

The preprint prints PISmith (Table 7) as each method's mean over the four AgentDojo v1.2.2 suites. These four files are
the aggregator reports those means were computed from, copied byte for byte from the run records,
with in-scope ASR scored by the paper's rule:

| file | arms |
|---|---|
| `fast_3119.md` | Undefended, MELON, Spotlighting, PI detector and SPILLWAY, in the order of its rows, then four empty DRIFT rows |
| `progent_133f.md` | Progent |
| `drift_a25f.md` | DRIFT |
| `rope_9b4e.md` | ROPE, with the agent's own model as its router. The values outside the brackets are its PISmith results. The bracketed values come from an earlier version of Figure 4 (Fig. 3 in the report's heading), and their utilities differ from the final Figure 4 and Table 8 |

Every cell was scored in full (144 Banking, 105 Slack, 140 Travel, 560 Workspace pairs). In-scope ASR is the in-scope hit
count over the scored pairs. The page build (`docs/_build/build_page.py`, Python 3.12 or newer) pins these files
by sha256, reads the suites from them, and fails unless each method's four-suite mean equals its Table 7 value to
within .0006.
