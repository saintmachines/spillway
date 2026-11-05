"""Appendix A table: per backbone x suite x method, raw (executed-effect) ASR and in-scope ASR (Table 1 grid), and the
AutoDojo levels. In-scope comes from final_v122.json (the values Table 1 prints); raw from tables_v122.json with the one
final_v122 note applied (qwen3:8b undefended Slack: one IT5 trace-only hit removed by ROPE's rule). Collision filtering
removes no hit in any cell (coll = 0 everywhere), so the collision-filtered level equals raw."""
import json, sys, re
F = json.load(open("final_v122.json")); T = json.load(open("tables_v122.json"))["cells"]
M = [("undefended", "Undef."), ("spillway", "SPILLWAY"), ("melon", "MELON"), ("progent", "Progent"), ("drift", "DRIFT"),
     ("spotlighting", "Spotl."), ("pi_detector", "PI det.")]
B = ["gpt-4o-mini", "qwen3-coder:30b", "qwen3:8b"]; S = ["banking", "slack", "travel", "workspace"]
f = lambda v: ("%.3f" % v).lstrip("0") if v < 1 else "%.3f" % v
rows = []
for s in S:
    rows.append("\\multicolumn{8}{l}{\\textit{%s}}\\\\" % s.capitalize())
    for b in B:
        cells = []
        for m, _ in M:
            t = T["%s|%s" % (b, s)][m]; fin = F["cells"]["%s|%s|%s" % (b, s, m)]
            ins = fin["asr"]; assert abs(ins - t["asr"]) < 1e-9 or (b, s, m) == ("qwen3:8b", "slack", "undefended")
            if m == "progent":
                raw = t["executed_hits"] / t["grid"]
            else:
                raw = t["raw_asr"]
            if (b, s, m) == ("qwen3:8b", "slack", "undefended"):
                raw = (t["hits"] - 1) / t["grid"]
            assert raw + 1e-9 >= ins
            cells.append("%s/%s" % (f(raw), f(ins)) if abs(raw - ins) > 1e-9 else f(ins))
        rows.append("\\quad %s & %s \\\\" % (b, " & ".join(cells)))
head = " & ".join(n for _, n in M)
print("\\begin{tabular}{l ccccccc}\n\\toprule\nCell & %s \\\\\n\\midrule\n%s\n\\bottomrule\n\\end{tabular}" % (head, "\n".join(rows)))
