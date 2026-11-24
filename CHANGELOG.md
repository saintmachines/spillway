# Changelog

## 1.1.0

- The opt-in `E2gV2Guard` also checks selected terminal effects before dispatch. It checks provenance for requests to lower runtime protections, delegate work to another agent, or edit a dependency declaration. Applications continue to own execution permissions.

- Add opt-in runtime checks for supported sensitive tool actions and approvals.
- Preserve the underlying evidence used by destination checks when applications
  change how tool responses are displayed.
- Support a fixed local approval judge for applications that configure one.
- Ship the SDK and defensive integration APIs in the registry distribution.
- Remove the `spillway-agentdojo` CLI from the PyPI distribution. Published
  evaluation results remain available in the GitHub measurement report.


## 1.0.1+e2g.2

- Add the opt-in E2g v2 guard over the public 1.0.1 SDK.
- Use the frozen e2f approval rules and D1 v2 rendering repair.
- Apply the standard Guard decision before E2 and discard the current creation receipt when E2 refuses the call.

## 1.0.1

- Repair target-presence checks when display serialization changes an original captured scalar value.
- Classify exact sender-address filters on declared local reads separately from outgoing recipients.
- Add empty-by-default, application-owned ResourceContracts/ResourceField declarations for reviewed typed resource fields.
- Retain source-pinned host bridges for an explicit AgentDyn integration; do not install or enable that integration by importing the SDK.
- Preserve public Guard defaults, optional local review and existing APIs. Host-backed AgentDyn results remain whole-stack measurements.
- Keep distribution contents limited to SDK source, metadata, documentation, license and notice. Workflow-feedback candidates008/009 are excluded.

The historical enhanced_014 policy identifier remains for API compatibility. Historical benchmark results and private measured wheels retain their original provenance.

The bundled CANDIDATE_014.md is preserved byte-for-byte as a historical configuration/API compatibility description; the current 1.0.1 scope is this changelog and README.
