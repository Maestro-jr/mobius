# themob: registration draft for the GenAI Works hackathon

A starting draft you can paste into and adapt to the form's actual questions.
Nothing here is submitted for you; edit freely.

## Name

themob: a mobile attack-surface intelligence engine with an autonomous,
grounded security agent.

## One-liner

An authorization-gated engine that scans a mobile app and lets you ask, in plain
language, what is wrong and how to fix it. An AI agent investigates by driving
the engine's own contained tools and answers from the real findings, never from
guesswork.

## The problem

Developers across Cameroon and the wider region are shipping mobile apps fast,
often AI-assisted, and security testing has not kept up: it is slow, expensive,
and needs a specialist. Generic scanners are noisy, do not prioritise, and do
not explain. And nothing is tuned to the local ecosystem: the mobile-money SDKs
(MTN MoMo, Orange Money), the local hosting and cloud choices, the frameworks
local teams actually reach for.

## What it does

themob runs a contained, sandboxed, multi-tool pipeline over an APK or an IPA
(androguard, apktool, jadx, gitleaks, semgrep, syft and grype, MobSF, and an iOS
Mach-O and Info.plist path), and turns the output into one deterministic,
de-duplicated, audited finding set mapped to MASVS and the OWASP Mobile Top 10,
on a single attack-surface graph. Every run is gated by an authorization
attestation and recorded on a hash-chained audit trail.

On top of that deterministic core sit three AI capabilities:

- **An investigation agent (the agentic-AI centerpiece).** You type a goal
  ("what are my worst issues and how do I fix them?"). The agent autonomously
  drives themob's own read-only tools across several steps, grounds every
  statement in the real findings, and hands back a prioritised, specific
  remediation plan. It is not a chatbot: it reasons over a reproducible,
  audited security graph, and it is built so it cannot invent a finding.
- **A local intelligence corpus.** It learns which weaknesses recur across your
  own scans and how often you confirm or dismiss each, and (opt-in and
  anonymised) can contribute to a shared picture of what actually breaks in the
  local app ecosystem.
- **A plain-language assistant.** A one-shot explain-and-fix for a single app.

## Why it fits an agentic-AI hackathon

The agent is the point. It is an autonomous, tool-using, grounded agent built on
an MCP tool server, with real safety rails: the tools are contained, the
side-effecting ones are gated and audited, and the answer is anchored to a
deterministic finding set so it cannot hallucinate vulnerabilities. It shows
agentic AI applied to a hard, verifiable domain, security, rather than a toy.
It also runs on free LLM tiers, so it is usable where paid APIs are a barrier.

## What is already built

- Full Android and iOS static pipelines, end to end.
- A deterministic finding model: canonical weakness keys, fingerprint
  de-duplication, cross-tool voting, MASVS and Mobile Top 10 mapping, scoring.
- An MCP tool server (19 contained tools) that the agent drives.
- A provider-agnostic LLM layer (Claude, or free providers such as Groq),
  the one-shot assistant, and the investigation agent.
- A local intelligence corpus, a Trends view, and opt-in anonymised telemetry.
- A PyQt6 desktop application, and over 1,100 automated tests.

## Tech

Python, PyQt6, sandboxed Docker workers (network-off, read-only, dropped
capabilities), SQLite, networkx, the MCP Python SDK, the OpenAI and Anthropic
SDKs behind one provider-agnostic layer, lief for Mach-O, and MASVS-mapped
knowledge packs.

## The differentiator

A security agent that is deterministic first: the findings are reproducible and
audited, and the AI is a grounded advisor on top, never the thing that decides a
vulnerability exists. Plus a corpus aimed at the real failure patterns of the
local mobile ecosystem.

## Team

(your name and role here)
