# SPILLWAY 1.0.1: SDK release and one mini host-variant check

The 1.0.1 release ships the reviewed SDK fixes and the frozen wheel `f93d56ecb11890af5a8381bd6ef1de916803e61f94137992b7e435ad93ff5c21`. Its package README and CHANGELOG remain part of the immutable release source. [Release notes](https://github.com/saintmachines/spillway/releases/tag/v1.0.1) · [PyPI](https://pypi.org/project/spillway-guard/1.0.1/).

The existing figures, videos, standard/stress tables and [1.0.0 measurement report](../RELEASE_014_RESULTS.md) keep their original provenance. The historical **.489** is a three-backbone × four-suite, twelve-cell mean. The new **.612** below is a four-suite mean for one mini backbone; it does not replace .489.

## Matched mini configuration, different judge host

Both columns use `gpt-4o-mini-2024-07-18`, AgentDojo 0.1.35/v1.2.2, the original task grid/scorer, target recovery ON, temperature 0, seed 42, max 8192 and the same 469-byte system prompt. The published reference used a Colab/CUDA judge; the new run used Studio/macOS/Metal. There is no same-host 1.0.0 counterfactual or paired confidence interval, so the observed difference does not establish a code effect, superiority or latency equivalence.

| Four-suite mini metric | Published v2 / 1.0.0 reference | 1.0.1 Studio/Metal host variant |
|---|---:|---:|
| Utility under attack, equal-suite macro | .608283730159 | .611855158730 |
| Benign utility, equal-suite macro | .674851190476 | .672321428571 |
| Standard-attack in-scope effects | 0/949 | 0/949 |
| Attacked task successes, pooled separately | 679/949 | 688/949 |
| Benign task successes, pooled separately | 69/97 | 69/97 |

The new run covers 949 attacked and 97 benign user UIDs in 8 logical cells. Workspace attacks were split into two disjoint 280-UID jobs; their union is the original 560-UID grid. Canonical auxiliary 35 records are tracked separately from user scores. Raw, executed and in-scope attack effects are all 0/949 for this run. The SDK's default application API does not automatically enable the benchmark's target-recovery profile or a host adapter.

| Standard attacked task successes | Reference | New host variant |
|---|---:|---:|
| Banking | 64/144 | 64/144 |
| Slack | 59/105 | 56/105 |
| Travel | 81/140 | 85/140 |
| Workspace | 475/560 | 483/560 |

This is one new mini run. The historical nine 1.0.0 repeats are a separate record. The new Qwen, ChatInject, AutoDojo and PISmith results are pending and are not filled with zeros. H10 host-workflow changes belong to the separately planned 1.0.2 release.

Reference: [arXiv v2](https://arxiv.org/pdf/2611.07222v2), [original public counts](https://github.com/saintmachines/spillway/blob/main/benchmarks/results/release_014_actual.json), and the completed 1.0.1 raw/scorer/UID/ledger independent audit. [Count and audit bindings](release-1.0.1-mini-host-variant.json) retain the independent receipt and source hashes; no new comparison-method rerun or statistical significance claim is made here.
