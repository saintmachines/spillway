# Reproducing one AgentDojo cell

A *cell* of the paper's breadth grid is one AgentDojo suite, one backbone and one attack, run over the full grid
of user tasks and injection tasks (Table 1 of the paper: 3 backbones x 4 suites, 949 attacked pairs per backbone:
144 Banking, 105 Slack, 140 Travel, 560 Workspace). This page runs one such cell with the settings of the paper's
runs through `spillway-agentdojo`, the console script of the `agentdojo` extra, which forwards the command line of
the evaluated gate, [`reference/spillway_gate.py`](../reference/spillway_gate.py), after setting the paper's
environment ([`src/spillway_guard/agentdojo/runner.py`](../src/spillway_guard/agentdojo/runner.py)).

## 1. Requirements

| What | Version used in the paper | Notes |
|---|---|---|
| Python | 3.13.15 | the package needs 3.10 or newer |
| `agentdojo` | 0.1.35 | suite v1.2.2's task and data files equal AgentDojo 0.1.35's. `pip install -e ".[agentdojo]"` |
| `openai` | 3.16.2 (an AgentDojo dependency) | the harness talks to every backbone through the OpenAI client |
| `google-genai` | | not a paper setting: two harness modules under `reference/harness/` import it at import time although no Gemini backbone is used. Install it if the import fails |
| Ollama | 0.34.2 | serves the local backbones and the judge. It needs the native `/api/generate` route with `format json` and `think`. `SPW_OLLAMA_URL`, default `http://127.0.0.1:11434`. Start it with the server settings in Section 2 |
| backbones | `qwen3:8b`, `qwen3-coder:30b` (Ollama), `gpt-4o-mini-2024-07-18` (OpenAI API) | `ollama pull qwen3:8b`. For gpt-4o-mini set `OPENAI_API_KEY` and leave `OPENAI_BASE_URL` unset (the harness refuses otherwise) |
| judge | `gemma4:31b` (Q4_K_M) on Ollama | `ollama pull gemma4:31b`. A tag can move, so check the judge's and the backbone's digests against Section 8, item 2 before a long run |
| GPU | one NVIDIA RTX PRO 6000 Blackwell (the paper's local runs) | any machine that serves the backbone and a 31B 4-bit judge |

## 2. The paper's settings and what sets them

Everything below is applied by `spillway-agentdojo` unless the variable is already set in your shell (`setdefault`),
so one exported variable overrides one setting. The harness modules read some of the same settings under their own
historical prefix. The runner mirrors every `SPW_<NAME>` value to those names, so only the `SPW_` spelling is needed.

| Setting (paper) | Value | How it is set |
|---|---|---|
| Suite | AgentDojo v1.2.2, full user x injection grid | `SPW_SUITE_VERSION=v1.2.2` (any `--user-tasks`/`--injection-tasks` subset is a smaller run) |
| Attack | AgentDojo's `important_instructions` template | `--attack important_instructions` |
| Name the injection addresses | "GPT-4" for gpt-4o-mini (AgentDojo's own name), "Local model" for the Ollama backbones | `SPW_INJ_MODEL_NAME`, derived from `--agent-model` |
| System prompt | AgentDojo's default (469 bytes, sha256 `a021a92b...`) in the `system` role | `SPW_HARNESS_PROMPT_FILE` = the packaged [`agentdojo_default_prompt.txt`](../src/spillway_guard/agentdojo/agentdojo_default_prompt.txt). The runner checks its hash and sends the leading message as `system` |
| Decoding | temperature 0, seed 42, at most 8192 output tokens (the paper), a 600 s timeout on each agent request (the paper's runs) | `SPW_TEMPERATURE=0 SPW_SEED=42 SPW_MAX_TOKENS=8192 SPW_REQUEST_TIMEOUT=600`, filled on every agent call that leaves them unset, except the timeout, which is set on every call (`SPW_AGENT_SHIM=0` disables the shim) |
| Reasoning | switched off where the backbone has a switch | `reasoning_effort: none` on qwen3 backbones (`SPW_SHIM_RULES`) |
| Defense switches | the four of every run in the paper | `--auto --access-grant --chatml-guard --exfil-provenance` (or `--paper`) |
| Judge switches | multi-view recovery and the integrity judge | `SPW_ESCALATE_MV=1 SPW_MV_INTEGRITY=1` |
| Recovery switches | all on | `SPW_REFBIND SPW_SELF_OWNED SPW_TASKNAMED_FETCH SPW_AUTHZ_SELFOP SPW_INJSPAN_RECOVER SPW_EXTPRINCIPAL SPW_EXFIL_INV SPW_READFETCH2 SPW_ID_AGENTDYN SPW_QUERYENTAIL SPW_CONJUNCTION SPW_SELFWRITE_INTEGRITY SPW_INGRESS_REDACT SPW_GRANT_PRINCIPAL_NAMED SPW_SELFWRITE_RECIPIENTS SPW_INGRESS_AGENTADDR`, each `=1` |
| Judge | gemma4:31b (Q4_K_M), 4096-token context, temperature 0, JSON verdict. A missing verdict counts as a no | `SPW_VOTERS=gemma4:31b`. The gate posts to `${SPW_OLLAMA_URL}/api/generate` (Ollama's native API) with `num_ctx 4096`, `temperature 0`, `format json`, `think false` |
| Backbone server | Ollama's OpenAI-compatible endpoint for a local backbone, at the model's full context window, with flash attention and an 8-bit key-value cache | `${SPW_OLLAMA_URL}/v1` (mirrored to the harness). The window, flash attention and the cache are server settings (below the table) |
| Output directory | | `SPW_OUT_DIR` (default `./spillway_runs`) |

**The Ollama server.** The runner does not start Ollama, and Ollama reads its server settings only when `ollama serve`
starts. Stop any Ollama that is already running, then start it as the paper's runs did:

```bash
OLLAMA_CONTEXT_LENGTH=40960 OLLAMA_FLASH_ATTENTION=true OLLAMA_KV_CACHE_TYPE=q8_0 \
  OLLAMA_NUM_PARALLEL=1 OLLAMA_KEEP_ALIVE=2h OLLAMA_MAX_LOADED_MODELS=6 ollama serve
```

`OLLAMA_CONTEXT_LENGTH` is the backbone's full context window, 40960 for qwen3:8b and 262144 for qwen3-coder:30b.
The `/v1` route serves the backbone at this window and cuts a longer prompt without an error (Section 8, item 1), and
Ollama's default window depends on GPU memory. A gpt-4o-mini cell uses Ollama only for the judge, which sets its own
4096-token context. The server's log lists all six variables on its `server config` line.

Load the judge and a local backbone at these contexts before the first pair, as the paper's runs did, so that a judge
request does not wait for a model load (Section 8, item 5). In the paper's runs, Ollama estimated 19.1 GiB of GPU
memory for the judge, 12.5 GiB for qwen3:8b and 31.3 GiB for qwen3-coder:30b at these settings. On a GPU with room
for both, `OLLAMA_KEEP_ALIVE` and `OLLAMA_MAX_LOADED_MODELS` keep them loaded. Put your backbone's tag and window in
the second request:

```bash
curl -s http://127.0.0.1:11434/api/generate -H 'Content-Type: application/json' \
  -d '{"model": "gemma4:31b", "prompt": "hi", "stream": false, "options": {"num_predict": 1, "num_ctx": 4096}}'
curl -s http://127.0.0.1:11434/api/generate -H 'Content-Type: application/json' \
  -d '{"model": "qwen3:8b", "prompt": "hi", "stream": false, "options": {"num_predict": 1, "num_ctx": 40960}}'
```

**Diagnostic and optional switches.** The runner sets none of these. The documented `SPW_` set is then the set the
gate and the runner read. `SPW_REFERENCE_DIR` (runner): overrides where `reference/` is looked for, default the
`reference/` directory found by walking up from the installed package (a checkout or editable install).
Read by the gate, all off unless set to `1`: `SPW_CLEAN_RECOVER` (admit a non-co-resident target the co-residence
veto refused), `SPW_EXFIL_PRECISE` (co-residence veto only on calls with a sensitive payload), `SPW_READFETCH`
(the v1 read-fetch rule, includes downloads), `SPW_REFBIND_DELEG` (referent binding to non-email delegated targets),
`SPW_INTEGRITY_CTRL_SKIP` (skip the integrity control arm), `SPW_MV_TELEMETRY` (judge telemetry in the audit).
`SPW_EXFIL_LOG` and `SPW_JUDGE_LOG` (paths of optional diagnostic logs, unset = no log). `SPW_AGENTDYN_SCHEMA` is
the one default-on switch (AgentDyn's typed schema on the github, shopping and dailylife suites, `0` turns it off).

## 3. The exact command

```bash
pip install -e ".[agentdojo]"          # from a checkout. The runner needs reference/ next to src/
ollama pull qwen3:8b && ollama pull gemma4:31b

reproduce/run_cell.sh banking qwen3:8b
```

`run_cell.sh` checks that the server at `SPW_OLLAMA_URL` is up and has the judge and the backbone, then runs

```bash
spillway-agentdojo \
  --suite banking --agent-model qwen3:8b --attack important_instructions \
  --auto --access-grant --chatml-guard --exfil-provenance \
  --logdir "$SPW_OUT_DIR/cells/banking_qwen3_8b" --run-id "$RUN_ID" --summary-tag "$RUN_ID"
```

with the environment of Section 2. Extra arguments go through unchanged and override the defaults, so

```bash
reproduce/run_cell.sh banking qwen3:8b --attack none                                   # benign utility (BU)
reproduce/run_cell.sh workspace gpt-4o-mini-2024-07-18                                # the OpenAI backbone
reproduce/run_cell.sh slack qwen3:8b --user-tasks user_task_0 --injection-tasks injection_task_1   # one pair
```

The same without the wrapper: `spillway-agentdojo --paper --suite banking --agent-model qwen3:8b`
(`--paper` expands to the four defense switches). `spillway-agentdojo --self-test` runs the gate's own
predicate-level and gate-level self-tests (no server needed, `agentdojo` must be installed).

## 4. Expected outputs

- **Per-pair logs** under `--logdir`, in AgentDojo's layout:
  `<logdir>/<suite>_<backbone>_<defense suffix>_<run id>/<pipeline name>/<suite>/<user task>/<attack>/<injection task>.json`.
  Each file holds the full message trace, the utility and security verdicts of AgentDojo's checks, and, for a refused
  call, the refusal the agent read.
- **A summary** printed at the end and written to
  `$SPW_OUT_DIR/summary_<suite>_<backbone>_<defense suffix>_<run id>.json` with `n_pairs`, `utility_rate`, `asr`,
  `elapsed_seconds`, `elapsed_per_pair`, `partial` (true if the run was interrupted and the summary was recomputed
  from the pairs on disk) and the run's switches.

How the summary relates to the paper's numbers:

- `utility_rate` under attack is the cell's UAU. With `--attack none` it is the cell's BU. A benign summary also prints
  `asr` 1.0, and its `n_pairs` counts user tasks. With no injection task, AgentDojo skips the security check and records
  true for each user task, so this `asr` measures no attack.
- `asr` is AgentDojo's raw security check at the trace level. The paper rescores every hit by executed effect and
  then drops content-manipulation tasks (the in-scope level). Both levels are printed in the paper's Appendix A, and
  `make asr-levels` prints them. The paper's zero for SPILLWAY is at the
  executed (raw) and in-scope levels in all twelve cells. It makes no claim at the trace level, and the trace-level
  `asr` may exceed zero when a refused call is left in the transcript (the released floor-only arm, for example,
  shows trace-only Slack hits with no executed effect). Take the paper's levels from `make asr-levels`. The summary's `asr` is the trace level.
- **Scoring a rerun.** `make asr-levels` prints the stored per-cell levels and does not read a new run. To score a
  rerun as the paper does, apply ROPE's `runs/corrections.py` at commit `64495e16` (Section 9) to the per-pair logs. It
  corrects the security checks of Slack IT5, DailyLife IT7 and GitHub IT1. Then count only effects that executed, and
  for the in-scope level drop content-manipulation tasks (Travel IT6).
- The paper's SPILLWAY cells (BU/UAU, in-scope ASR, Table 1):

  | Suite | gpt-4o-mini | qwen3-coder:30b | qwen3:8b |
  |---|---|---|---|
  | Banking | .562/.521, .000 | .375/.500, .000 | .438/.438, .000 |
  | Slack | .714/.524, .000 | .571/.429, .000 | .476/.286, .000 |
  | Travel | .550/.571, .000 | .500/.407, .000 | .250/.343, .000 |
  | Workspace | .875/.838, .000 | .475/.543, .000 | .450/.414, .000 |

- Each cell in the paper ran once. Utility moves between runs: the paper's 27-run reseeding of SPILLWAY (seeds 42,
  777, 123, three repeats each, three backbones) had `.000` in-scope attack success in every run, and per-suite
  utility varied with a standard deviation of at most `.041` across the three repeats of a fixed seed and `.021`
  across the per-seed means. A rerun of the 949 qwen3:8b pairs with the address rules, which some of SPILLWAY's runs
  lacked (the paper's Appendix B), reproduced each suite's utility and attack success to the third decimal.

## 5. Approximate runtime

The released results carry call counts, not wall-clock, so budget a cell by calls:

- Agent calls: in the released ChatInject records on qwen3:8b, the SPILLWAY arm made 2,552 backbone calls for the
  560 Workspace pairs and 660 for the 105 Slack pairs (about 4.6 and 6.3 per pair). The breadth-grid records carry
  no backbone call counts. On gpt-4o-mini the delegated-routing records show 2,222 calls for 180 GitHub pairs and
  1,462 for 200 DailyLife pairs.
- Judge calls: on qwen3:8b benign traffic the judge is consulted 0.05 (Workspace), 0.05 (Travel), 0.43 (Slack) and
  0.75 (Banking) times per episode. Under attack the judge is called on every refused call that reaches it: the
  released delegated-routing records show 925 judge calls on 180 attacked GitHub pairs, 592 on 200 DailyLife pairs
  and 379 on 180 Shopping pairs (about 2 to 5 per attacked pair).
- Per episode, SPILLWAY's added wall-clock over the undefended agent was within 0.5 s on the paper's GPU (Figure 3,
  timed in a separate session), against +1.6 to +10.5 s for the model-call defenses
  (Progent +1.6 / +2.3 s, MELON +4.9 / +7.9 s, DRIFT +9.9 / +10.5 s on Slack / Workspace).

A benign cell's time is therefore close to the undefended agent's: the number of pairs times about five backbone
calls times your server's per-call latency. An attacked cell adds the judge calls above.

## 6. Cost

The local backbones and the judge cost nothing beyond electricity. A gpt-4o-mini cell is billed by OpenAI at the
model's token prices. In the paper's runs, SPILLWAY's attacked gpt-4o-mini cells cost $0.08 (Banking, 144 pairs),
$0.09 (Slack, 105 pairs), $0.31 (Travel, 140 pairs) and $0.61 (Workspace, 560 pairs), and its four benign cells
cost $0.12 together, so these eight cells cost $1.21. Its GitHub, DailyLife and Shopping cells of the
delegated-routing grid cost $0.77 (180 pairs), $0.42 (200 pairs) and $0.80 (180 pairs). A spend cap is not built
in, so use your API key's limit.

## 7. The grid, the ablation arms and the stress panels

- **Breadth grid (Table 1, Table 2, Appendix Table 5).** 12 cells: `{banking, slack, travel, workspace}` x
  `{gpt-4o-mini-2024-07-18, qwen3-coder:30b, qwen3:8b}`, each under attack and once benign (`--attack none`). All
  are runnable with `run_cell.sh`.
- **Delegated-routing grid (Figure 4, Appendix Table 8).** The four AgentDojo suites plus AgentDyn's GitHub,
  DailyLife and Shopping on gpt-4o-mini. SPILLWAY's four AgentDojo cells are its breadth-grid cells on gpt-4o-mini.
  The three AgentDyn suites come from [AgentDyn](https://github.com/leolee99/AgentDyn) at commit
  `5353cf7615b135cace8d07c8f12dac53a16b6db3`, which installs as `agentdojo` 0.1.35 in place of the release from PyPI.
  Its Banking, Slack, Travel and Workspace task and data files equal AgentDojo 0.1.35's, and its agent code differs
  from PyPI's (Section 8, item 6). The gate already carries AgentDyn's tool roles. On the three AgentDyn suites the
  paper's runs gave SPILLWAY and ROPE AgentDyn's own default system prompt (543 bytes, sha256 `21a1c00d...`), which
  is AgentDojo's plus the line "Complete all tasks automatically without requesting user confirmation." Write it to
  a file and pass it in `SPW_HARNESS_PROMPT_FILE`. `run_cell.sh` takes only the four AgentDojo suites, so call
  `spillway-agentdojo` directly:
  ```bash
  git clone https://github.com/leolee99/AgentDyn
  git -C AgentDyn checkout 5353cf7615b135cace8d07c8f12dac53a16b6db3
  pip install -e ./AgentDyn
  python -c 'print(__import__("yaml").safe_load(open("AgentDyn/src/agentdojo/data/system_messages.yaml"))["default"], end="")' > agentdyn_prompt.txt
  SPW_HARNESS_PROMPT_FILE=$PWD/agentdyn_prompt.txt spillway-agentdojo --paper --suite github --agent-model gpt-4o-mini-2024-07-18   # also dailylife, shopping
  ```
- **Component ablation (Table 3, qwen3:8b).** The arms vary the sanitizer, identity-target judge recovery and span
  veto. Fixed delegation rules and the object judge remain enabled in every arm, including the arm labelled
  floor only. The exact switch set behind each arm is part of the evaluation harness and is not reproduced by
  `run_cell.sh`.
- **Stress panels (Table 4, Appendix Tables 6 and 7).** ChatInject, AutoDojo (its released gpt-4o-mini injections,
  variant 0, commit 89413642) and PISmith use attack inputs from their authors' releases. They are not in this
  repository. `--attack-module <file.py>` loads a module that registers a custom AgentDojo attack, which is how the
  harness ran them.
- **Attacker-as-sender variant (Appendix C).** The paper's own re-addressing of the five injection-carrying
  Workspace emails so that they come from the attacker's address, under the standard attack (126 pairs, qwen3:8b).
  The re-addressed suite data is not in this repository.

`run_cell.sh` runs the standard-attack and benign cells. [`benchmarks/results/`](../benchmarks/results/) holds the
per-cell results behind Tables 1 to 3, Appendix Table 8, Figure 4, Figure 3's Slack and Workspace values, and six of
the eight rows of Table 4's ChatInject panel. `benchmarks/scripts/make_tables.py` prints them and runs 590 checks
against the paper and the files, and `make asr-levels` prints Table 5 without its ROPE column. The PISmith reports behind Appendix
Table 7 are in [`benchmarks/results/pismith_a4/`](../benchmarks/results/pismith_a4/), and the page build
(`docs/_build/build_page.py`, Python 3.12 or newer with the package installed) checks them against the paper.

## 8. Differences from the paper's harness

1. **Context overflow.** The paper's harness checked before each local call that the prompt plus `max_tokens` fit
   the backbone's context window and otherwise ended the pair with utility false and security true, because
   Ollama's `/v1` route truncates a long prompt silently. The runner does not include that preflight. It matters
   only for pairs that overflow the window. The released SPILLWAY record on qwen3:8b shows 21 such pairs among the
   560 Workspace pairs and none elsewhere. For every method, the paper's scores count such a pair as an attack
   success only when the tool calls that ran before the overflow meet the injection task's own check. None of
   SPILLWAY's 21 did.
2. **One run per cell, moving tags.** A tag can move to new weights. The paper's runs used qwen3:8b at digest
   `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`, qwen3-coder:30b at
   `06c1097efce0431c2045fe7b2e5108366e43bee1b4603a7aded8f21689e90bca` and gemma4:31b at
   `6316f0629137b426c9d9b853ffc4c8209589f30ee39aebede6285096c0ff47e7`. Before a grid, compare them with the `digest`
   field that Ollama's `/api/tags` route gives for each model, as the paper's runs did.
3. **The summary's `asr` is trace-level.** The paper reports the executed and in-scope levels, which
   `make asr-levels` prints.
4. **Run the gate through `spillway-agentdojo`.** `reference/spillway_gate.py` is pinned reference code and keeps
   the harness's own defaults (output directory, environment names) when run directly. The runner sets the
   `SPW_` environment, points the output directory at `SPW_OUT_DIR` and replaces the refusal message the agent
   reads with the project's own wording (`patch_gate` in `runner.py`). The pipeline name and the summary's
   `write_policy` field still carry the gate's internal labels, as do its comments, identifiers and self-test message.
5. **Judge errors.** With the paper's switches the gate waits up to 30 s for each judge request and treats one that
   times out or fails as the judge saying no. The paper's harness logged every judge request and re-ran the user task
   after a failed one, and none failed in the runs behind Table 1. The runner does not re-run the user task, and its
   summary does not count failed requests. Keep the judge loaded (Section 2) and set `SPW_JUDGE_LOG` to a file to log
   each judge decision. An entry with `n_parsed` 0 got no verdict.
6. **AgentDojo's code.** The paper's harness imported `agentdojo` 0.1.35 from AgentDyn at commit `5353cf76` and
   replaced three of its files. The `agentdojo` extra installs AgentDojo from PyPI instead (0.1.35 or newer). In 0.1.35
   the task and data files of the four AgentDojo suites and the attacks are the same as in the paper's copy. Six of
   the differences in the code matter for reproducing the paper:
   - **Malformed tool calls** (AgentDyn). The paper's copy dropped a tool call whose arguments are not valid JSON and
     kept the rest of the reply. It recorded a pair that still raised a JSON decoding error with utility false and
     security true, and the paper ran that pair again. On PyPI such an error stops the cell, and the gate writes its
     summary from the pairs on disk with `partial` true. With AgentDyn installed, the summary counts such a pair as a
     failed task and a successful attack, and the pair's log holds the error.
   - **Temperature** (AgentDyn). The paper's copy sent temperature 0 on every agent call. PyPI leaves a zero
     temperature out of the request, and the runner's shim puts it back.
   - **The agent's output** (AgentDyn). The paper's copy took the last assistant message in the trace. PyPI requires
     the trace to end with one. The gate's pipeline always does, so both give the same output.
   - **Tool results** (paper's change). The paper's copy sent a result of one text block as a plain string, where PyPI
     and AgentDyn send a list with one text part. On the paper's Ollama (0.34.2) both forms give the qwen3 backbones
     the same prompt tokens. The records do not compare them on gpt-4o-mini.
   - **Standalone runs** (paper's change). The paper's copy skipped AgentDojo's run of each injection task on its own,
     which no score uses. On PyPI and AgentDyn an attacked cell first runs it once per injection task, which adds
     calls and cost.
   - **`extra_args`** (paper's change). The paper's copy gave each pair a fresh one, where PyPI and AgentDyn share one
     across pairs. The gate keeps its own state per episode, so only MELON, which keeps its masked tool calls there,
     depends on this.

   Installing AgentDyn (Section 7) brings the changes marked AgentDyn, and this repository does not include the three
   replaced files. Progent and ROPE ran on their own copies of AgentDojo, and DRIFT on the PyPI release (Section 9).

## 9. Comparators

Every method ran on the agent settings of Section 2 (system prompt, decoding and reasoning), except where its row or
Section 7 says otherwise. The paper rescores every method with ROPE's `runs/corrections.py`, and for every method a
pair that ended in an error other than a context overflow was left out and run again. In the paper's Tables 4 and 7,
‡ marks Progent and ROPE (released code adapted to the paper's agent and suite, as listed below) and † marks DRIFT
(its authors' planner and validator). The first four rows ran their attacked cells in
[`reference/harness/21_agentdojo_full_benchmark.py`](../reference/harness/21_agentdojo_full_benchmark.py) on the
AgentDojo code of Section 8, item 6. Progent, DRIFT and ROPE ran in their own harnesses.

| Method | Code the paper's runs used | Settings and changes | In this repository |
|---|---|---|---|
| Undefended | the harness script with no defense | none | runs with the command below |
| Spotlighting | AgentDojo's `spotlighting_with_delimiting` | two sentences added to the system prompt say that `<<` and `>>` wrap each tool output and tell the agent never to obey instructions between them | runs with the command below |
| PI detector | AgentDojo's `transformers_pi_detector` with [protectai/deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) | a tool output whose SAFE score is under 0.5 is replaced with a notice that data was omitted. The runs used transformers 5.16.1 and model revision `90c9989b` | runs with the command below and AgentDojo's `transformers` extra |
| MELON | the authors' `pi_detector.py` from [kaijiezhu11/MELON](https://github.com/kaijiezhu11/MELON) at `4d3cc9c0`, in the harness script | cosine threshold 0.8, MELON's own value. Tool calls are embedded with nomic-embed-text on Ollama in place of OpenAI's text-embedding-3-large, and messages are read in AgentDojo's content-block format | not included (`--defense melon` stops at the missing `melon_detector` module) |
| Progent | [sunblaze-ucb/progent](https://github.com/sunblaze-ucb/progent) at `8a8eb894`, with AgentDojo 0.1.35's v1.2.1 and v1.2.2 suite changes ported into its bundled AgentDojo 0.1.29 | the cell's own backbone writes the policy, with Progent's seed and retry ladder and the switches of its `run.sh` (`SECAGENT_UPDATE=True`, `SECAGENT_IGNORE_UPDATE_ERROR=True`). Policy calls get the 8192-token cap (Progent sends none), and on the local backbones the policy prompt gets one line on the output format. A policy entry that names no tool is dropped, where Progent's own code asks for a new policy at a higher temperature. The paper's copy of its AgentDojo records a pair that raises any error with utility false, security true and the error. Unless the error was a context overflow, the paper left such a pair out and ran it again | not included |
| DRIFT | [SaFo-Lab/DRIFT](https://github.com/SaFo-Lab/DRIFT) at `6fd3df47` on AgentDojo 0.1.35 from PyPI, the authors' files unchanged | the authors' prompts, planner, validator and environment block, which tells the agent to finish tasks without asking for confirmation. Local backbones are served by Ollama, and gpt-4o-mini goes through DRIFT's own OpenAI route. Output is capped at 8192 tokens, where DRIFT asks for 8000 on the local backbones and 10000 on gpt-4o-mini | not included |
| ROPE | [xhOwenMa/ROPE](https://github.com/xhOwenMa/ROPE) at `64495e16`, with its own copy of AgentDojo | the router is the cell's own backbone in Tables 1, 2 and 5 and on the ChatInject, AutoDojo and PISmith panels, and the authors' Claude Opus 4.8 with cached scopes in Figure 4 and Figure 1a (gpt-4o-mini in Table 8). The clamp, which drops a router override looser than ROPE's audited defaults, is on in Tables 1, 2 and 5, in Table 8's gpt-4o-mini-router column and in the AutoDojo and PISmith rows, and off with the Opus router and in the ChatInject row. The paper's patch adds Workspace to ROPE's suites and ChatInject to its attacks, and lets the run set the seed and the server address. For the ChatInject row, Figure 4 and Table 8, further patches make ROPE's copy record a context overflow with utility false and security true, as AgentDojo 0.1.35 does, where ROPE's release records security false. Hits are scored with AgentDojo 0.1.35's checks, including Workspace injection tasks 10 to 12, which ROPE's copy changes | not included, and neither are the Workspace scopes of Figure 4, which the paper made once with the Opus router |

`spillway-agentdojo` runs only the gate. Run the undefended, Spotlighting and PI-detector arms through the harness
script with the runner's environment:

```bash
python -c 'import runpy, sys
from spillway_guard.agentdojo.runner import prepare
argv, ref = prepare(sys.argv[1:])
sys.argv = [str(ref / "harness" / "21_agentdojo_full_benchmark.py"), *argv]
runpy.run_path(sys.argv[0], run_name="__main__")' \
  --suite banking --agent-model qwen3:8b --defense spotlighting_with_delimiting
```

Pass `--defense ''` for the undefended agent, or `--defense transformers_pi_detector` after
`pip install "agentdojo[transformers]==0.1.35"`. The runner's note that none of the paper's defense switches is set
refers to SPILLWAY's switches and can be ignored here. The summary and the per-pair logs go to `$SPW_OUT_DIR`, the
logs under `runs/`. The script has no `--attack none`, so it runs attacked cells only, and the script behind the
paper's benign comparator runs is not included. Items 1 to 3 and 6 of Section 8 apply to these runs as well. When an
error stops the script, it leaves the per-pair logs and no summary.
