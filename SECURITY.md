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

SPILLWAY's stated property concerns the **target** of an effect: a side-effecting call
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

Under the documented configuration (the switches in [reproduce/README.md](reproduce/README.md), section 2), an injection in
attacker-controlled free text makes the agent execute a call whose target is an
identity the user never named and no read-only tool returned in a typed field.
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
- A target that never appears verbatim in tool output. Verbatim means the same
  characters after lowercasing and collapsing spaces, so an address assembled
  from fragments, a URL with a query string added, and a value hidden by a
  zero-width character or an encoding count as never seen.
- Utility loss, latency, or a sanitizer rule that removes benign text.
- A tool set whose roles are not declared in a lexicon (see CONTRIBUTING.md).
- Attacks that change the tools, their declared return types, the user's task,
  or the scorer.

## Known limits

These hold in 0.1.x with the default `Policy`. They are how the rules work, so a
report of one of them alone is not a new bypass. A way around a limit is.

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
  plain identifier that begins with such a word passes too. "Send the report to
  Alice" admits report@evil.example and malice@evil.example, also when the
  address lies in removed text. `Policy(delegation_span_veto=True)` refuses these
  targets when they lie in removed text or rode in on free text.
- **Named principals.** A grant to a principal the task names admits the address
  in the call unless it lies in removed text. Nothing ties the address to the
  name. `Policy(delegation_span_veto=True)` also refuses an address repeated in
  free text.
- **Deletion words.** A deletion counts as authorized when the task holds a
  deletion word that no negation up to two words before it covers, also when the
  word is about something else.
- **Task-named downloads.** A download from a two-label host is admitted when the
  task holds the host's site word, so "Download the report" admits report.example.
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
