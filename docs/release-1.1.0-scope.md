# SPILLWAY 1.1.0

Install the SDK with `pip install spillway-guard==1.1.0`. Use `E2gV2Guard` to check tool proposals for selected terminal effects and protected file access. Configure the local D2 reviewer for supported sensitive approvals. Your app resolves file identities and enforces permissions at dispatch.

The release includes E2g v2, frozen D2, the v3b terminal checks, file policy v2.1 L0, and a fix for JSON verdicts from the default local Gemma judge. For Ollama on a custom host or port, set `extra_body={"reasoning_effort": "none"}` when constructing `Judge`. Existing `Guard` integrations continue to use the same default policy. The PyPI package includes the SDK and the AgentDojo contract helper. The paper and its historical reproduction records remain on GitHub.

## Evaluation scope

| Evaluation | Tested configuration | Observed results |
|---|---|---|
| AgentDyn normal tasks, Gemma 4 31B | SDK wheel `a047c8785363` with the Studio host, its benchmark runner's system prompt and 15 rounds | 43/60 completed without defense and 21/60 with the SDK |
| Same AgentDyn tasks | SDK wheel `a047c8785363` with verified attachment access `bfef1275` and destination guidance `a9d5c46e` | 25/60 completed, a gain of four tasks with all 21 prior completions retained |
| Gray Swan IPI public command-tool subset, Qwen3‑VL‑235B | E2g v2 and frozen D2 compared with the v3b research build `466451d5`, then with app-level file policy v2.1 | Among 53 inputs repeated three times, goal executions went from 18/159 to 0/159 for both v3b configurations. Original tasks completed during attacks were 58/159, 61/159 and 53/159 across the three conditions. Normal completions were 32/48, 32/48 and 28/48. |

AgentDyn uses the original 60 normal tasks across DailyLife, GitHub, and Shopping. The two added checks are host integrations. The full PISmith 949-pair measurement on this release wheel remains open. For Gray Swan, the goal execution count comes from the public command-tool subset and the recorded research configuration. The release wheel was checked separately on installed-SDK and normal app tests. In two local workspaces, all 12 normal tasks completed and none of the protected file operations returned private content or saved changes.

See the [integration guide](https://saintmachines.github.io/spillway/integrate.html), [research results](https://saintmachines.github.io/spillway/results.html), and [Gray Swan IPI publication](https://arxiv.org/abs/2603.15714).

## Release files

| Artifact | SHA-256 |
|---|---|
| `spillway_guard-1.1.0-py3-none-any.whl` | `a047c87853638b7faee3c4b32a36d2d8456f5db098fbdaf93416e6bb545a4209` |
| `spillway_guard-1.1.0.tar.gz` | `0660f75d6a8793dc86c05677c42b22cae4d9a563b7ec512f9ad46cde821946f1` |
