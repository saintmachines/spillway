# SPILLWAY reference implementation: file checksums

`reference/spillway_gate.py` is the final build of the gate the paper evaluated, with the evaluation harness's
environment names replaced, and `reference/harness/` holds the four modules it imports. Comments, identifiers, the
pipeline label and the self-test message keep internal code names such as Holdfast, DARE, SENTINEL and v12 to v15,
which have no meaning outside the project. Some of the paper's results, among them
SPILLWAY's cells in Table 1 and its ChatInject row in Table 4, ran on an earlier build without the address and
payee-change rules. Appendix B of the paper reports that these rules change no sanitizer output on the 27,392 tool
messages behind Tables 1 and 3, the ChatInject panel and Figures 3 and 4, and that rerunning Table 1's 949 qwen3:8b
pairs with the address rules reproduces each suite's utility and attack success to the third decimal. This file pins the evaluation gate and its artifacts. The library API under `src/` is versioned separately, and `CHANGELOG.md` records its checks and regression coverage. The result
files and the script below are the ones behind most of the paper's tables
(`benchmarks/results/README.md` says which). No number in the result files was changed from the
run outputs. Most internal labels, paths and notes were renamed or removed, some keys were dropped, some keys and the
`producer` and `src` fields keep the harness's own names, and the two
breadth-grid files also hold ROPE's twelve cells and their Table 2 means, computed from ROPE's scored attack and
benign runs. The four PISmith reports behind Table 7 (`benchmarks/results/pismith_a4/`) are pinned in
`docs/_build/build_page.py` (`PIS_SHA`). Run the gate through `spillway-agentdojo`
([reproduce/README.md](../reproduce/README.md)), which
sets the paper's switches. The project page's build recomputes every checksum below and those of the PISmith reports,
and stops on a mismatch. It needs Python 3.12 or newer with the package installed (`pip install -e .`). Run it as
`python docs/_build/build_page.py --out <dir>/index.html` with an existing `<dir>`, so that `docs/` stays as it is.

## Files

| File | sha256 |
|---|---|
| `reference/spillway_gate.py` | `bc08ab7ae1d707301f2ff9d27e0fb36c2370fc9f387b21a3ec83baca9f187083` |
| `reference/harness/21_agentdojo_full_benchmark.py` | `8bf864719888e5a3aaa5896d1433941d00e9263d4f769df3482ef8ceacaf1a1a` |
| `reference/harness/24_agentdojo_gemini_backbone.py` | `5b26216cc6f8b8d9a224c280f9c521009e4e2777778e65e7a6c13a90da5a9bbf` |
| `reference/harness/27_agentdojo_v8_action_boundary.py` | `106fa7a304ec57055663f7563c2a3b8625b6c1fd0f3eea27aef3a0cc6c350a6b` |
| `reference/harness/30_agentdojo_v12_taint_gate.py` | `8dc7e3eaad2bdc51c829fd363a9210d986fb78392a10090abfbb186bd126b5b8` |
| `benchmarks/results/ablation_and_chatinject.json` | `6ebabefdfdca877520722b3f3993ee080c6f5e846d98bd9442dd0084d371c5d3` |
| `benchmarks/results/ablation_no_span_veto.json` | `6a08059b3b9b16dd7516359431dbdec5ca95b606002fdef662916d1c3a4b8a0c` |
| `benchmarks/results/breadth_grid_cells.json` | `f0d054b753cf1564ecbddbe90d978e833c5704e5074d4cb618d98c835e909882` |
| `benchmarks/results/breadth_grid_summary.json` | `f3d977076391b1a4cd1efa91f4f55b635085821db1d35054e549cf51f8a8420c` |
| `benchmarks/results/delegated_routing_agent_router.json` | `1d8ff44395d4df15db9a2940959feda00d7bb1d70b34532a986a65324d963276` |
| `benchmarks/results/delegated_routing_opus_router.json` | `fe153d4097afc7116e7ead9d865792cef219de6d36f11706bc7e06b6c510c0fa` |
| `benchmarks/results/fig_cost_values.json` | `67a22cfc5fc20cdb64d534de9e387c04fcb244cd23925b4a46b7cab8fd032a39` |
| `benchmarks/scripts/appendix_asr_levels.py` | `a1c668846ba40fad560cee9399f459807da8c55af21bf2b9a3829c0710e4f9d1` |
