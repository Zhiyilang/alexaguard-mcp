# Gradio November Hackathon — Submission Guide (AgentGuard)

**Track 1: Building MCP** — the hackathon wants a *functioning MCP server*.
AgentGuard already **is** one. This repo packages it as a Gradio Space that
exposes the same tools over MCP (`/gradio_api/mcp/`) plus a human-friendly UI.

## What's ready (AI-built, you only deploy + post)

- `app.py` — **dual-mode entry point**:
  - HF Space (`SPACE_ID` env set) → launches Gradio UI + MCP server.
  - Any other host → serves the Streamable-HTTP MCP server (Amazon Alexa+ track).
- `agentguard.py` — zero-dependency deterministic safety core (guard_text / redact / guard_messages).
- `mcp_http.py` — Streamable HTTP MCP transport (spec 2025-11-25).
- `requirements.txt` — `gradio[mcp]>=5.0` (used only in Space mode).
- `eval.py` — **69/69 assertions pass** (deterministic, offline).

## 3 MCP tools exposed

| Tool | Purpose |
|---|---|
| `screen_text` | verdict (allow/refuse/sanitize) + 0-100 risk + rule-id'd findings |
| `redact_text` | PII → `[REDACTED]` (CN mobile / ID / bank card / email / landline) |
| `moderate_text` | OpenAI-moderations-shaped flag vector |

> ⚠️ **官方 hackathon tag 必填（铁律）**：本仓 `README.md` 已含 HF Space 元数据前缀
> （title/emoji/sdk/tags 等），但 `tags` 里的 `hackathon` 是**占位**。窗口开启后，
> 去官方 rules 页复制**确切的 hackathon tag**（形如 `gradio-november-hackathon-2026`，
> 以官方为准），替换 `README.md` 的 `tags` 中 `hackathon` 那一项。
> **tag 错/漏 = 评委检索不到 = 无效提交**，务必核对。

## Your steps (window 2026-11-14 → 11-30, must be NEW during window)

1. **Create a NEW HF Space** (https://huggingface.co/new-space) named e.g. `agentguard-mcp`,
   pick **Gradio** SDK. Do this *during* the window.
2. Upload this repo's files (`app.py`, `agentguard.py`, `mcp_http.py`,
   `requirements.txt`, `README.md`, `LICENSE`) into the Space — or `git clone` +
   push. The Space README must include the track tag (see below).
3. Confirm the Space builds and `/gradio_api/mcp/` answers `tools/list`.
4. **Post** a short X/LinkedIn note with the Space link (required by rules).
5. Record a 1–5 min demo (use `oa_demo`-style: show a malicious prompt being
   refused, then a PII string being redacted). Upload to YouTube.
6. Submit on the hackathon page before 11-30.

## Space README snippet (paste at top of the Space's README)

```
---
title: AgentGuard — Agent Safety Guardrail MCP Server
emoji: 🛡️
colorFrom: red
colorTo: gray
sdk: gradio
sdk_version: "5.0"
app_file: app.py
pinned: false
tags:
  - mcp
  - gradio-mcp
  - security
  - agents
  - guardrails
---

# AgentGuard — Building MCP (Track 1)

A functioning MCP server that guards agent-facing HTTP endpoints...
```

## Eligibility note

Confirm on the official rules page that mainland China is not excluded before
submitting (Devpost-style global hackathons usually only exclude
Brazil/Quebec/Cuba/Iran/North-Korea/Crimea/Russia; China has been safe in
sister events — re-verify at window open).
