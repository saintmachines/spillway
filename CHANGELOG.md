# Changelog

## 0.1.4

- Use one enhanced SDK and AgentDojo default: whole-target checks, source/domain binding, application-declared typed identities and resource-kind evidence. Keep source-value research rules off.
- Default verified in-memory AgentDojo source/create contracts after checking version and implementation bytes. Other hosts register their own reviewed contracts.
- Let URLs captured from successful read-tool executions reach the existing content judge. Pasted-only, unseen and changed URLs remain subject to the fetch precondition; observed tool text is not automatic authority.
- Deliver actionable refusal feedback through the model-visible error channel and exclude the guard's own emissions from future evidence. Do not reduce or execute repaired calls automatically.
- Preserve all typed objects when collecting original strings from list returns. Retain the complete-target punctuation and numeric-pagination fixes.
- Keep historical paper results separate from updated artifact-bound model measurements.

## 0.1.4rc4 — private alignment candidate

- Share the SDK whole-value referent predicate at both live reference entry points. A delegation that fails this predicate can still reach the original subsequent ladder; the legacy opt-out restores the original helper.
- Treat terminal question punctuation after a user-named email as prose while retaining whole-identifier and URL-query boundaries.
- Preserve rc3 evidence separately. Fresh package and caller validation is required for this candidate; no model benchmark or public release is implied.

## 0.1.4rc3 — private integrated release candidate

- Enable strict user-directed URL fetch checks by default; provide an explicit previous-policy opt-out. Preserve path/query case and check dotless HTTP hosts, IP literals and nested URL containers.
- Add separate instruction/pasted-text fields and strict nonce boundary validation. Pasted material cannot supply its own authority or typed identity schema.
- Add the explicit `Policy.enhanced_014()` deployment profile: source/domain checks, application-declared identity and scoped short-resource provenance. Verified transport and create-new registrations remain host-owned configuration.
- Retain finite R5 value/fragment checks as research options. Document legitimate document-link refusal and untyped-schema integration costs separately from attack decisions.
- Prepare source-bound package, executor and fixed-call benchmark checks. Historical paper model metrics are not new candidate measurements; publication has not been performed.

## 0.1.4rc1 — isolated research candidate

- Add `Policy.ground_targets=False`: a whole-target presence precondition inside the gate, before judge/delegation. Short targets are checked; arbitrary observed tool text is not typed provenance.
- Add `Policy.trusted_target_aliases=False`: restricted deterministic email/URL/IBAN spelling aliases derived only from the original user task. No typo guessing, Unicode transliteration, or tool-text alias promotion.
- Connect `--ground-targets`, `--trusted-target-aliases`, and `--delegation-span-veto` to the AgentDojo runtime gate without editing frozen reference files.
- With `ground_targets`, the URL of a fetch must be grounded too, read-only tools included (`Policy.ground_fetch_urls`, on by default; off restores the inbound fetch exemption). A rebuilt or data-appended fetch URL is refused, and a grounded one still meets the content tier.
- An identifier that occurs in the user's request only inside a longer identifier (a prefix of a user-named URL, a parent domain of a user-named address) is refused even when tool text repeats it.
- A URL target is compared with and without `http://` or `https://` and a trailing slash.
- In the user's request, a period glued to a Capitalized word ends the lower-case identifier before it (AgentDojo slack user_task_4 writes "www.our-company.com.They").
- Aliases never join prose into an identifier: a dot with whitespace only after it, or before a Capitalized word, is not folded, so "bob@acme.example. It is urgent" never yields a new domain. A comma is never read as a dot.
- Aliases from the user's request also cover full-width ASCII, invisible characters inside an identifier, and a spelled-out bare host that carries a path or two dots. Tool text is never read this way.
- Keep recorded benchmark numbers and existing defaults. No new model evaluation, efficacy estimate, or public release is claimed.

## 0.1.3

- Integrate guarded recovery v1 G1/G2 into identity and object two-view recovery; preserve exact tool-channel sources across judge resumes.
- Enable ROLEMARK ingress matching by default. Identity-target recovery remains opt-in.
- Add independent opt-outs and a separate guarded AgentDojo reference; `--paper` keeps the frozen v1 path.
- Clarify selected-call judge scope. No new model evaluation or new benchmark numbers are claimed.

All notable changes to SPILLWAY are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

## [0.1.2]

### Changed

- `Policy.escalate_mv` now defaults to `False`. The optional judge no longer restores a refused identity target through the two-view target-recovery path. `mv_integrity` and other policy fields are unchanged. `Policy(escalate_mv=True)` restores the prior target-recovery behavior.
- The reference runner defaults target recovery to OFF unless `--paper` selects the recorded ON setting or `SPW_ESCALATE_MV=1` opts in. The original full-system SPILLWAY results used recovery ON.

### Added

- `spillway-agentdojo --no-identity-target-recovery` disables the two-view recovery of refused identity targets across both public and historical environment aliases. Object-case recovery and other settings are preserved. The existing library option is `Policy(escalate_mv=False)`.
- Caller-level regression checks cover stale aliases, unchanged object recovery, the default paper configuration and the separate payload escalation option.

### Clarified

- Reported zeros apply to the stated benchmark conditions. A judge may admit an unsafe target that the deterministic check did not approve. Disabling identity-target recovery may also refuse legitimate delegated work.
- Recorded paper results are not relabeled as results of the new default. This release does not claim a completed adaptive evaluation.

## [0.1.1]

Package description, metadata and recorded example. The library's code is unchanged apart from
this version string, so every decision and benchmark value stays as in 0.1.0.

### Changed

- The description on PyPI, the README and the project page open with the results
  and link the paper on arXiv (2611.07222).
- The package metadata names SAINT Machines as author, the project page as
  homepage, the integration guide as documentation and the arXiv record as the
  paper.
- The recorded example shows all eight methods on the qwen3:8b Slack episode
  (user task 8, injection task 1). Its actual outcomes and the separate guard
  check are shown separately.
- Browser demonstration assets are excluded from the source distribution.

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
  (lint, unit tests on Python 3.10 to 3.14, differential tests against the
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

[Unreleased]: https://github.com/saintmachines/spillway/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/saintmachines/spillway/releases/tag/v0.1.1
[0.1.0]: https://github.com/saintmachines/spillway/releases/tag/v0.1.0
