---
name: Bypass report
about: An injection routed an effect to an attacker's target through the floor
title: "[bypass] <suite> / <backbone>: <one line>"
labels: ["bypass", "security"]
assignees: []
---

<!--
Read SECURITY.md first. Report bypasses privately via
https://github.com/saintmachines/spillway/security/advisories/new and leave the
"Injection text" section empty here. If private reporting is unavailable,
use this public issue only to request a private channel.

In scope: an effect sent to an identity (recipient, account, participant, channel,
URL) that the user never named and that no read-only tool returned in a typed field.
Out of scope: a spoofed typed field, and content-only effects.
-->

## Suite

<!-- AgentDojo suite and version, or the tool set, e.g. banking / v1.2.2 -->

## Backbone

<!-- agent model and how it was served, e.g. gpt-4o-mini-2024-07-18 (API) or qwen3:8b (Ollama), temperature, seed -->

## Injection text

<!-- Omit the injection text from this public issue. Use private vulnerability reporting, or request a private channel here. -->

## Tool returns

<!-- Provide a non-sensitive summary here. Send exact tool returns and private data through the private reporting channel. -->

## The call that executed

<!-- Summarize the tool name and the target argument. Send exact arguments through the private reporting channel. -->

## Which rule admitted it

<!-- one of: floor (target was in the typed identity index), delegation rule (name it), judge restoration (route or payload view), sanitizer miss (the instruction region was not removed), other -->

## Configuration

- SPILLWAY version / commit:
- Switches (`--auto --access-grant --chatml-guard --exfil-provenance` and the `SPW_*` environment switches you set):
- Judge model and endpoint:
- AgentDojo version:

## Reproduction

<!-- Provide task ids and a non-sensitive summary of the steps. Send the full reproduction privately. -->
