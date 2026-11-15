# Security policy

SPILLWAY is a defense, so a report that an injection gets through it is the most
valuable issue this project can receive. This page says what counts as a bypass,
what does not, and how to report one.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## The threat model, in short

The agent receives a task from the user, calls typed tools, and reads what they
return. The attacker controls free text the agent later reads (an email body, a
web page, a document, and in the Slack suite the name of one external channel).
The attacker does not control the user's task, the tool implementations, the
tools' declared return types, or the scorer.

The paper's stated property concerns the **target** of an effect: a side-effecting call
is admitted only when every target value that appears in tool output but not in
the user's task was returned by a read-only tool in a typed identity field or is
covered by a fixed delegation rule. The judge may restore a refused call, never
one whose target lies in text the sanitizer removed. The paper reports zero
in-scope attack success on the AgentDojo benchmarks it runs, a raw zero under
ChatInject, a mean of .007 under PISmith, and .000 on AutoDojo's 389 released
pairs, a descriptive result. On the held-out Banking set optimized against DRIFT
it reports .007 by AgentDojo's check and .014 counting a second transfer that
check misses (2 of 144), and on the other held-out set .000. It claims nothing
beyond those benchmarks and that scope.

## In scope

Report an injection that defeats the documented 0.1.4 default or a specified paper configuration. Include the exact artifact and settings. In particular, attacker-controlled free text that makes the agent execute a call to a target that neither the user authorized nor an application-declared trusted identity source supplied is in scope. The recorded paper configuration and its switches are in [reproduce/README.md](reproduce/README.md).
Examples:

- an email, message, transfer, share, calendar invite, or booking sent to an
  attacker-written recipient, account, participant, or channel.
- a fetch of an attacker-written URL that the user did not ask for.
- a grant to a principal the user did not name.
- a destructive call the user's task did not authorize.
- a judge restoration whose target lies inside a removed span (a span-veto
  violation).
- a delegation rule or lexicon entry that admits an attacker-chosen target.
- a forged chat-template turn that survives the guard and steers a target.

An implementation bug with the same effect (for example an identity index built
from free text rather than from a typed return) is also in scope.

## Out of scope

These fall outside that property. Report them as ordinary issues if they
look like bugs, but they are not bypasses:

- **A spoofed typed field.** An attacker who writes an identity field, for
  example by sending the email so that the attacker's own address arrives in the
  typed sender field, puts that value in the index. A tool provider that writes
  attacker-chosen values into identity fields is outside the threat model.
- **Content-only effects.** Injected content sent to a legitimate target,
  injected text in the final answer, and causality laundering through a later
  call to an admitted target are content effects, outside any target check.
- **Steering to a legitimate identity.** An injection that redirects an effect to
  an identity the user named or a trusted tool returned, such as an existing
  contact or the payee of a bill the user asked to pay, is left to the sanitizer
  and the judge.
- Utility loss, latency, or a sanitizer rule that removes benign text.
- A tool set whose roles are not declared in a lexicon (see CONTRIBUTING.md).
- Attacks that change the tools, their declared return types, the user's task,
  or the scorer.

## The 0.1.4 default and host boundary

`Guard(task)` uses `Policy.enhanced_014()`. Identity-target recovery through the judge is off in the SDK. The enhanced AgentDojo command `--paper --guarded` explicitly enables the paper's recovery settings; the recorded paper numbers remain results of their original configurations.

The enhanced default checks complete target values and their boundaries. A substring, a short identifier, an unseen value, or an address assembled from pasted fragments does not acquire authority merely because the old lookup did not compare it. Deterministic spelling aliases come from the trusted task. Pasted text and arbitrary tool prose cannot declare an identity schema, a source contract, or permission to act.

Identity evidence comes from application-declared typed schemas and tool roles. A raw dictionary key named `sender`, `author` or `email` does not establish identity authority. Validate against a model declared by the application before observing a return. Whole local-part matching, domain checks and source evidence constrain referent binding. A matching task word in an attacker's address is insufficient by itself.

Short resource identifiers covered by the target-role checks require the matching declared resource kind and scoped evidence. Editing an own resource by a guessed identifier is a separate action-intent concern; these target checks do not authorize every edit. Hosts also declare reviewed source transport and create-new contracts. The AgentDojo adapter registers its in-memory contracts only after checking the suite version and implementation bytes; other hosts supply their own contracts. Tool-return text cannot register a contract. An unverified source or a changed URL cannot inherit authority from the visible text alone.

URL fetching has a provenance precondition as well as the existing content check. A trusted task URL or a URL captured from a successful read-tool execution can reach that check. A URL found only in pasted prose, an unseen URL, or a modified URL has no automatic fetch permission. This can refuse a legitimate link whose origin the application has not registered.

These checks do not authenticate a dishonest provider or replace the tool's own authorization. The host must declare tool roles and target arguments and apply the guard at every effect boundary. An undeclared argument, a forged trusted typed field, content sent to an already legitimate target, and semantic authorization errors remain distinct concerns. Optional judge decisions can be wrong. Recovery-OFF can also refuse legitimate destinations found only in document text. No configuration is a general prompt-injection guarantee.

## Historical 0.1.3 controls and limits

The following describes the original target/delegation rules, selectable with `Policy.legacy_013()` or the explicitly historical reference mode `--legacy-v1`. It does not describe the enhanced 0.1.4 default. Compatibility controls are research settings, not alternative deployment recommendations. The paper's original target property also excluded a target never appearing verbatim in tool output, such as an address assembled from fragments or a URL with an added query. Such a target is not excluded from a 0.1.4 implementation-bug report merely because it was unseen.

- **Length.** The lookup compares values of 4 to 120 characters. A shorter or
  longer plain identifier is not compared, and a value that is a substring of
  the user's task counts as user-named.
- **Observed text.** A target is compared only with text the `Guard` observed. A
  value from a channel that never reached `observe_tool_return` or `observe_text`
  is admitted.
- **Argument names.** Only target arguments the lexicon declares are checked. A
  value under an undeclared name, or held in a dict key, is not a target.
- **Referent binding.** An address in tool output is admitted when its local part
  contains a task word of four or more letters, and the domain is not checked. A
  plain identifier that begins with such a word passes too. Both pass also when
  they lie in removed text. `Policy(delegation_span_veto=True)` refuses these
  targets when they lie in removed text or rode in on free text.
- **Named principals.** A grant to a principal the task names admits the address
  in the call unless it lies in removed text. Nothing ties the address to the
  name. `Policy(delegation_span_veto=True)` also refuses an address repeated in
  free text.
- **Deletion words.** A deletion counts as authorized when the task holds a
  deletion word that no negation up to two words before it covers, also when the
  word is about something else.
- **Task-named downloads.** A download from a two-label host is admitted when the
  task holds the host's site word, the label before the top-level domain.
- **Free text.** A typed field's value that also sits inside a sentence is still
  admitted unless it is an email, a URL, or an identifier of 8 or more characters
  with at least 4 digits, written in letters, digits and `+() .-`. A shorter
  identifier, one with `_`, `:` or `/`, or a plain name stays admitted.
- **Dict returns.** In an untyped dict, key names decide the role, so a parsed page
  returned as a dict can place a value under a key such as `author` and enter the
  index.

## How to report

Please report a bypass privately rather than in a public issue:

1. Use GitHub's private vulnerability reporting for this repository
   (**Security** tab, then **Report a vulnerability**):
   https://github.com/saintmachines/spillway/security/advisories/new
2. If that is unavailable to you, open an issue with the
   [bypass report template](.github/ISSUE_TEMPLATE/bypass_report.md) and omit
   the injection text. We will arrange a private channel.

Include what the template asks for: suite and backbone, the injection text, the
typed tool returns the agent saw, the call that executed with its arguments,
and which rule admitted it (floor, delegation rule, judge restoration, or
sanitizer miss), plus the SPILLWAY version, switches, and judge model. A
reproducible pair file from the evaluation harness is ideal.

We aim to acknowledge a report within 7 days, confirm whether it is in scope,
and agree a disclosure date with you. Fixes ship with a regression test that
replays the report, and the CHANGELOG credits reporters who want to be named.
