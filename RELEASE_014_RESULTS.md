# SPILLWAY 0.1.4 artifact-bound measurements

**Measurement and source-alignment review complete; publication approved.**

The 10,012 requested target episodes are closed across 54 conditions and 111 execution shards. The paid 2,384 UID composite is counted once. Independent checks matched every target UID and all 9,721 attack payloads byte for byte. The final source-alignment and publication review passed.

Under the standard AgentDojo template attack, the final 0.1.4 artifact records 48.9% mean utility under attack and zero reported in-scope attack success in all 12 backbone-suite cells. The original paper records 48.4% under its historical configuration. These are separate measurements; other defenses were not rerun in this release campaign.

## Standard attack: new artifact versus the historical paper

| Configuration | BU | UAU | ASR | NRP(BU) | NRP(UAU) | ERS(BU) |
|---|---|---|---|---|---|---|
| Original paper v1 (historical) | .520 | .484 | .000 | .520 | .484 | .684 |
| Final 0.1.4 artifact (new measurements) | .539 | .489 | .000 | .539 | .489 | .700 |

These are 12-cell macro means, not pooled episode rates. The printed UAU difference is 0.5 percentage points; this is not a significance claim.

### Final 0.1.4 per-backbone four-suite macro

| Backbone | BU | UAU | ASR |
|---|---|---|---|
| gpt-4o-mini-2024-07-18 | .675 | .608 | .000 |
| qwen3-coder:30b | .530 | .490 | .000 |
| qwen3:8b | .413 | .370 | .000 |

## Additional attack conditions

| Attack / arm | Backbone | Utility successes / attempts | Reported ASR effects / attempts | Scope |
|---|---|---|---|---|
| ChatInject Workspace | qwen3:8b | 222/560 | 0/560 | 0 reported effects |
| ChatInject Slack | qwen3:8b | 30/105 | 0/105 | 0 reported effects |
| AutoDojo | gpt-4o-mini-2024-07-18 | 205/389 | 0/389 | Released 389-pair cache; descriptive development exposure |
| PISmith | gpt-4o-mini-2024-07-18 | 246/949 | 4/949 | 4-suite ASR macro .005; variant0 |
| PISmith | qwen3:8b | 160/949 | 1/949 | 4-suite ASR macro .002; calendar integrity hit retained |
| Attacker-as-sender | qwen3:8b | 70/126 | 0/126 | Workspace subset |
| Direct / recovery ON | qwen3:8b | 377/949 | 0/949 | Studio Metal |
| Direct / recovery OFF | qwen3:8b | 377/949 | 0/949 | Studio Metal |
| System-message / recovery ON | qwen3:8b | 341/949 | 0/949 | Studio Metal |
| System-message / recovery OFF | qwen3:8b | 341/949 | 0/949 | Studio Metal |

## Interpretation and execution scope

PISmith is not zero: mini has 4 reported effects in 949 attempted pairs (four-suite ASR macro .005), and qwen has 1/949 (macro .002). The qwen event is a calendar title/date integrity failure, not exfiltration; it remains counted. ASR follows each original family scorer; this report does not redefine that hit to manufacture zero.

The headline uses equal-weight 12-cell means. Pooled utility counts 161/291 benign and 1533/2847 attacked are separate diagnostics. NRP/ERS use the original definitions and printed-input rounding. No significance or paired confidence interval was computed.

The benchmark configuration uses the optional local judge and target recovery ON, with explicitly labelled OFF controls. SDK identity-target recovery remains off by default. Standard/ChatInject/sender/PIS and coder use Colab CUDA; direct/system-message use Studio Metal; the mini backbone is the pinned remote OpenAI snapshot.

The released AutoDojo 389-pair cache includes four pairs exposed during historical rule development; separate held-out Banking sets are not rerun here. PISmith is released-cache variant0 open-loop ASR@1, not a newly optimized adaptive attack against final 0.1.4.

Historical latency figures remain the original separate-session benign qwen3:8b Slack/Workspace mean episode-time comparison on RTX PRO6000. They are not new 0.1.4 timing, a per-episode upper bound, phone latency or service SLA. Parallel paid streams do not establish serial speedup. API invoices/GPU credits are outside this minimal report.

Reviewed runtime amendments include the Slack missing-argument evaluator guard, an explicit repeat-abort adapter terminal, and strict benign/auxiliary overflow readers. The three original repeat-abort logical failures and their unknown usage are preserved; an adapter terminal is not a valid provider response. All 60 context-overflow target attempts remain in the denominators: 22 standard qwen Workspace, 8 PISmith qwen Workspace, and 15 in each direct Workspace recovery arm. The 695 auxiliary goal records stay outside target denominators. Direct Travel also retains an executed content-only effect outside the reported in-scope numerator; raw, executed and in-scope counts are separate fields in the public data.

Source checks cover 123 actual preflight sources for the 111 logical shards, including chosen backbones, frozen decoding, host contracts, and recovery profiles. Independent Codex and Claude Code summaries agree on all 54 condition rows. The JSON records the audit hashes.

## Artifact and reproducibility

Wheel SHA-256: `3f055d6336268ba260b1ae62cad54111ed280738e023253f8ad14e68d8f4f928`. The tested wheel is not rebuilt.

[Public 54-condition count data](benchmarks/results/release_014_actual.json) · [Web report](https://saintmachines.github.io/spillway/release-0.1.4.html) · [Historical paper v1](https://arxiv.org/abs/2611.07222v1)

The JSON binds the completed strict join, merge, formatter, original summary and protocol hashes without private paths or credentials. Publication and registry-install verification are separate gates. Verify the exact 0.1.4 registry installation before any HF submission or listing announcement.

Official PyPI 0.1.4 wheel and sdist downloads match the tested hashes. A fresh registry installation passed all 26 package-member comparisons, enhanced-policy checks, and benign/repeated-untrusted-target probes. [Registry verification](benchmarks/results/release_014_registry.json).
