# Contributing to SPILLWAY

Thanks for helping. Three kinds of contribution are most useful: a bypass report
(an injection that gets an effect to an attacker's target through the floor), a
tool-role lexicon for a tool set the floor does not cover yet, and fixes with a
test. Keep the floor deterministic: no model call decides admission.

## Setup and tests

```bash
git clone https://github.com/saintmachines/spillway
cd spillway
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
ruff check .
pytest -q -m "not differential"
```

The differential tests run synthetic tool messages and typed models through the
packaged floor and through `reference/spillway_gate.py` (the final build the paper
evaluated) and require identical decisions on those inputs. The library checks
and their regression cases are recorded in `CHANGELOG.md` and
`tests/test_hardening.py`. A deliberate behavioral difference from the archived
gate belongs in both records. The differential tests
need the AgentDojo extra. Set `SPW_REQUIRE_DIFFERENTIAL=1` so that a missing
dependency fails the run instead of skipping it:

```bash
pip install -e ".[dev,agentdojo]"
SPW_REQUIRE_DIFFERENTIAL=1 pytest -q -m differential
```

Add such a test to `tests/test_differential.py`, whose tests carry the
`differential` mark. CI runs both groups on pushes to `main` and on pull
requests.

## Adding a tool-role lexicon for a new tool set

The floor reads where a call goes from the tools' declared types, never from
text. What it needs per tool set is a role lexicon, written once:

1. **Verb prefixes** that mark a tool as read-only, writing, destructive, or
   granting (the AgentDojo lexicon has 11, 22, 10, and 11 of them).
2. **Target-argument names**: the arguments that name where an effect goes
   (recipient, account, participant, channel, URL, with 26 names for AgentDojo and
   6 more for AgentDyn).
3. **Principal-argument names**: the arguments that name who receives a grant.
4. **Self-owned tools**: the short list of tools that write only to the user's
   own calendar or drive.
5. **Identity field types and routing roles** on the tools' return models: a
   field is indexed when its declared type is an identity format (email, URI,
   UUID, hostname, IP) or its field has a routing role (recipient, sender,
   participant, channel).

Then:

- Add a classmethod to `Lexicon` in `src/spillway_guard/lexicon.py`, like
  `for_agentdyn`, and pass the result to `Guard` through `lexicon`. Keep an existing
  lexicon as it is when you cover a new tool set.
- Add a test that runs the new tool set's benign tasks with the gate on and off
  and shows which calls the floor refuses and why. A refusal on benign traffic
  indicates a lexicon gap. Correct the role declarations and rerun the check.
- Confirm the change is a no-op on the AgentDojo suites: the differential tests
  must still pass unchanged.
- Say in the pull request which tool set, how many tools in each role, and which
  identity fields the index picks up.

## Reporting an attack that bypasses the floor

An injection that routes an effect to an identity target the user never named is
a security report. Follow [SECURITY.md](SECURITY.md) and send it through the
private channel described there. The fields a report needs are listed in the
[bypass report template](.github/ISSUE_TEMPLATE/bypass_report.md). A utility
regression, a sanitizer rule that removes benign text, or a content-only effect
is a normal issue.

## Conventions

- Python 3.10 or newer, standard library first. `pydantic` and `PyYAML` are the only
  hard runtime dependencies. `agentdojo` stays optional.
- Environment switches use the `SPW_` prefix.
- Every result in the documentation traces to `benchmarks/results/*.json` or to
  the paper. Do not add a result that neither source carries. Operational figures
  from the paper's runs, such as GPU memory and API cost, are labelled as such.
- Claims stay within the threat model: zero in-scope attack success on the
  AgentDojo benchmarks the paper runs, nothing wider than that.
- `ruff check .` and `ruff format .` before you push (line length 120).
