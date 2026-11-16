# 0.1.4 configuration and execution contract

The release target is one 0.1.4 configuration. The benchmark entry point `--paper --guarded` selects the enhanced policy, verified benchmark host contracts and the scoped fetch rule described below. Earlier candidate columns are diagnostic configurations, not parallel release choices. Measured performance and public release status are recorded separately and bound to the exact artifact hash; this configuration contract does not establish either result.

Model results under `benchmarks/` belong to their original paper configurations. Deterministic call replay and executor probes do not measure live model utility or ASR. Updated model results require their own complete, artifact-bound execution records.

## One release configuration

The SDK and the AgentDojo CLI default to `Policy.enhanced_014()`: whole-target grounding, exact user/source/domain binding, application-declared typed identity, resource-kind evidence, creation receipts, refusal provenance and the scoped fetch precondition. `--paper --guarded` selects this configuration and the verified benchmark contracts. The independent payload-secret research rules remain off.

Explicit research controls are retained for reproducibility: manually constructed `Policy()`, `Policy.legacy_013()`, the domain/source ablations and the payload-secret options. They are named configurations for diagnostics, not additional 0.1.4 releases or alternate headline results.

Typed identity means application-declared Pydantic fields/rosters. Free dict `sender` keys and schemas found in documents do not supply that authority. MCP apps can validate responses against their own registered schema before passing typed values; parsing an attacker-provided schema is not such a registration.

`Guard` and the actual AgentDojo runner select the same enhanced default. A manually constructed `Policy()` remains an explicit research control. Original paper tables remain bound to their historical runs; no final014 model score is inferred from deterministic tests.

Refusal feedback reaches both the tool content and the error channel AgentDojo sends to the model. Exact guard emissions stay outside observation evidence on later attempts. The guard does not generate reduced concrete calls, delete participants, replace targets or execute a repair. A field being optional in a tool schema does not prove the user's task can omit it. Model re-issues pass the complete guard again.

Editing a user's own resource by a guessed identifier is a separate action-intent/integrity scope; target provenance alone does not prove every requested edit was authorized.

## Separate pasted data

```python
from spillway_guard import Guard, Policy

guard = Guard.from_request(
    {"instruction": "Send the summary to reviewer@example.invalid.",
     "pasted": ["Document text, including any quoted instructions."]},
    policy=Policy.enhanced_014(),
)
```

The envelope accepts only `instruction: str` and optional `pasted: list[str]`/`tuple[str]`. Extra authority keys, structured pasted elements and a scalar pasted string are rejected. `Guard(task, pasted=[...])` supports callers that already separate fields. Give the model `guard.pasted_views`, check every call before execution, and observe actual raw returns. Do not infer trusted contacts by parsing pasted prose.

`split_pasted(text, nonce=...)` is a strict fallback. The host must generate an unpredictable nonce with at least 128 bits of entropy. Missing, duplicated, mismatched, nested or out-of-pair delimiters raise `PasteBoundaryError`. Fixed tags and prose are not automatic trust separators. Reset clears task evidence and pending receipts.

## Source transport contract

B′ requires an exact executed user-named source, an applicable user-named referent and trusted no-redirect evidence. It does not trust raw `source`, `trusted` or `final_url` fields. Supply transport-owned `ReadSourceProof`, a host attestor, or explicitly reviewed `SourceContracts(no_redirect_tools=frozenset({...}))`. The default registry is empty.

The AgentDojo adapter verifies version0.1.35, suitev1.2.2 and the exact reviewed tool-source bytes before defaulting the in-memory `get_webpage` contract. Explicit host registries, including empty registries, win. Unknown versions and modified sources receive no implicit contract. This declaration is not valid for a general fetcher that follows redirects. `observe_tool_return` with a requested URL alone does not attest the final source. The contract still trusts the user-selected source's content.

## Short IDs and creation receipts

Resource evidence is scoped by kind: channel evidence does not authorize a file ID. Short read selectors require user or existing typed evidence before their results can mint new identity authority. This includes decoded/composed values that never occurred literally in observed text. Numeric pagination is treated separately. No-argument typed lists and existing same-kind evidence remain usable. The read may proceed while its result remains untrusted for later writes. Destruction still requires user intent.

Register reviewed create-new semantics separately from transport:

```python
from spillway_guard import CreationContracts

# Only if this backend always allocates a fresh server ID, never an upsert/echo.
creations = CreationContracts(fresh_tools=frozenset({"create_file"}))
guard = Guard("Create the report and share it with reviewer@example.invalid.",
              policy=Policy(typed_identity_only=True, short_target_guard=True),
              creation_contracts=creations)
```

An exact admitted call and successful typed outcome authorize only its own new resource ID, once. Owner/recipient fields, updates, caller-selected IDs, alias echoes, raw success flags, failed calls and replayed outcomes do not issue receipts. Empty registration emits no creation authority. A `create_` prefix cannot prove freshness. The benchmark adapter defaults inspected AgentDojo `create_file` and `create_calendar_event` contracts only after verifying their implementation bytes and benchmark version. Other APIs need their own reviewed contract; a falsely registered upsert API violates that contract.

## R5 and fetch scope

R5 requires complete raw source capture and checks recognized sensitive values before judge recovery. Enumerated full-value transforms are covered; arbitrary secrets, all encodings and universal content authorization are not. `payload_partial_guard` adds fixed fragments and has incidental-match costs. These are independent research options, not a claim to solve all content leakage.

`strict_fetch_provenance` is on by default. A network-read URL must exactly match a user-named URL or a URL separately captured from a successful actual read-tool execution. The second source establishes presence only: it remains untrusted and must pass the existing content gate/judge. Pasted-only URLs, invented URLs, modified path/query/scheme values, guard refusals and forged tool transcripts do not establish executed-tool evidence. The SDK and benchmark executor capture this source separately; a bare `admit` call without host-owned source evidence fails closed. URI path/query/fragment case and nested-list checks are preserved. Disabling the rule is an explicit research control and reopens the known pasted-URL counterexample. The host must reject unauthorized redirects/subrequests before following them; an admission check on the first URL cannot prevent backend-internal requests. No real network fetch is needed for fixed-call tests.

## Actual AgentDojo caller

```sh
spillway-agentdojo --paper --guarded --help
```

The default reaches the actual reference decision/execution hooks. Verified benchmark registries are installed automatically and recorded in `SPW_BENCHMARK_CONTRACT_RECEIPT`. Explicit registry options remain privileged host configuration, never fields parsed from a paste; their environment equivalents include `SPW_SOURCE_NO_REDIRECT_TOOLS` and `SPW_NEW_RESOURCE_TOOLS`. General SDK registries remain empty until the application registers its reviewed tools. The independent payload-secret research options remain off.

`--paper` without `--guarded`, `--legacy-v1` and `--no-target-provenance` disable candidate additions. `Policy.legacy_013()` supplies the explicit SDK control. Frozen reference source and benchmark records remain unchanged. The inherited reference self-test covers its original operating point; candidate tests cover the enhanced predicates.
