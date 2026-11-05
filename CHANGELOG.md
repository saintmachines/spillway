# Changelog

All notable changes to SPILLWAY are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

## [0.1.0]

Initial release. `reference/spillway_gate.py` is the final build of the
gate the paper evaluated, and every number in the paper comes from it or from
an earlier build. The `spillway_guard` package ports it, and differential tests
compare their decisions on synthetic inputs. The library checks and their regression coverage are recorded below.
`reference/BUILD_PROVENANCE.md` pins the evaluation artifacts used for the reported tables.

### Added

- `spillway_guard` package: the typed-identity egress floor (identity index read
  from typed tool returns, taint-novel check, grant and destruction checks,
  fixed delegation rules), the rule-based ingress sanitizer that removes
  instruction-like regions and retains the removed spans as evidence, and the
  optional two-view judge with the span veto (disabled by default, enabled in the paper's
  results), which may restore a refused call but never one whose target
  lies in the removed text. `Policy(delegation_span_veto=True)`, off by default
  (the paper's setting), extends the span and co-residence veto to the
  delegation rules and to grants to a named principal.
- `spillway-agentdojo` (the `[agentdojo]` extra): runs the gate as a drop-in
  AgentDojo pipeline element with the switches used in every run of the paper
  (`--auto --access-grant --chatml-guard --exfil-provenance` and the `SPW_*`
  environment switches).
- `benchmarks/results/`: the per-cell numbers behind most of the paper's
  tables (its README says which), and
  `benchmarks/scripts/appendix_asr_levels.py` (`make asr-levels`), which
  prints the raw and in-scope attack-success levels of the paper's Table 5
  without its ROPE column.
- Packaging and community files: `pyproject.toml`, `CITATION.cff`,
  `CONTRIBUTING.md`, `SECURITY.md`, a bypass-report issue template, and CI
  (lint, unit tests on Python 3.10 to 3.13, differential tests against the
  reference gate, a build check).

### Library checks and regression coverage

`spillway-agentdojo` runs the archived evaluation gate in
`reference/spillway_gate.py`. The reusable library API maintains the checks
below. Each path has a test in `tests/test_hardening.py`, and `SECURITY.md`
lists the integration conditions and remaining admission paths.
Replaying recorded tool calls through the package before and after these
changes, without a model, changed none of 7,831 AgentDojo decisions. On 4,259
AgentDyn calls from an earlier run it refused 2 more with the judge fixed at yes
and 284 more with no judge. This replay checks fixed-call decisions. Task-level utility and attack success
are the paper's evaluation results, whose build lineage is recorded in
`reference/BUILD_PROVENANCE.md`.

- Delegation rules: every target of a call, a number included, must be bound to
  the task, a value that holds an address or a URL no longer passes on its first
  word, and a digit run no longer makes a value an identity attribute.
- Task-named fetches: a task word must name the URL's host, a parent domain counts
  only when written in full, and only URL arguments count. `fetch_*` and
  `browse_*` tools get the content check.
- Grants: a principal must be named in the task as a whole word, numeric member
  ids count as principals, and a `transfer` tool counts as a grant only when it
  moves an owner or a repository.
- Free text: an IBAN or another opaque identifier repeated inside a sentence
  counts as repeated in free text.
- Decoy spans: a harmless removed span no longer opens the injection-span rule.
  `Policy(injspan_clean_rule=True)` restores the evaluated rule.
- Span veto: forged chat turns join the removed spans, a sign-off removes the
  sender's name only at the claim, and the grant rule honors removed text.
- Taint: returns are also compared as raw strings, so a target with a character
  the renderer escapes still matches.
- Arguments and fields: target values are read at any depth, camelCase names
  split into words, and free-text names such as `email_body` are never targets
  or identity roles. `attendees`, `invitees`, `guests` and `shared_with` are
  target arguments.
- Deletions: an intent word must be a whole word that no negation covers, so
  "clearly", "cancellation policy" and "do not delete" no longer authorize a
  deletion.
- Judge: only a true verdict restores a call, an exception counts as a no,
  `Judge(threshold=...)` takes effect, a panel counts every model, and a long
  argument no longer pushes a target out of the prompt.

### Results in the paper (AgentDojo suite v1.2.2 and AgentDyn)

- Standard attack, three backbones x four suites: in-scope attack success
  `.000` on all twelve cells, at the highest twelve-cell under-attack utility of
  the defenses run (`.484`) and 96% of the undefended agent's benign utility.
- ChatInject (forged chat template, qwen3:8b, 665 pairs): raw zero.
- AutoDojo (optimizer-generated injections): in-scope attack success `.000` on
  the 389 released pairs (descriptive). On two held-out Banking sets, `.000` and
  `.007` by AgentDojo's check, `.014` counting a second transfer that check
  misses.
- PISmith (released RL attacker): mean in-scope attack success `.007`.
- Delegated routing against ROPE, seven suites on gpt-4o-mini: in-scope attack
  success zero on all seven.

Some of these results, among them SPILLWAY's cells in Table 1, ran on an earlier
build without the address and payee-change rules. Appendix B of the paper
reports that these rules change no sanitizer output on the 27,392 tool messages
behind Tables 1 and 3, the ChatInject panel and Figures 3 and 4, and that
rerunning Table 1's 949 qwen3:8b pairs with the address rules reproduces each
suite's utility and attack success to the third decimal.

### Scope

- The stated property is scoped to identity targets: a recipient, account, participant,
  channel or URL that the user never named and that no read-only tool returned
  in a typed field. A spoofed typed field and content-only effects are out of
  scope. See `SECURITY.md`.
- Target roles come from one lexicon per tool set. A new tool set needs its roles
  declared before the floor covers it. See `CONTRIBUTING.md`.

[Unreleased]: https://github.com/saintmachines/spillway/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/saintmachines/spillway/releases/tag/v0.1.0
