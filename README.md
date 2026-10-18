# AgentGuard MCP

A **zero-dependency, self-hosted MCP server** that turns the AgentGuard
deterministic safety engine into an Alexa+–compatible Agent Skill. It screens
agent inputs, tool arguments and retrieved documents for prompt injection,
jailbreak, privilege escalation, tool coercion, exfiltration and PII — and
returns a structured verdict with no model call, no network, and no false
positives on benign traffic.

Built for the **Amazon Developer Hackathon 2026 — Alexa+ track**
(Build, Ship, Shape). The server speaks the **MCP Streamable HTTP transport,
protocol `2025-11-25`**, which is exactly the spec the track requires.

## Why

AgentGuard was originally built for the 7th China AI Competition "Agent Safety
Protection Challenge" and is calibrated against five real misjudgement classes
observed on an August adversarial message set. It is deterministic and fully
offline, so any agent can call it as a guardrail without adding latency,
cost or a model in the loop.

The same engine is reused across four competition submissions (China AI
Safety Challenge, Dubai Create AI Agents Championship, Gemma paper, Songjiang
AI Game), so this MCP server is the shared, reusable safety surface.

## Tools

| Tool | Input | Output |
|------|-------|--------|
| `screen_text` | `{text}` | `{decision, risk, findings[], reasons, pii, redacted}` — full verdict |
| `redact_text` | `{text}` | `{redacted, pii_redacted}` — PII masked copy |
| `moderate_text` | `{text}` | `{flagged, categories{}}` — OpenAI-moderations-shaped vector |

`decision` is one of `allow` / `refuse` / `sanitize`. PII in the user's own
message is masked and logged, **never refused** (input PII is not an attack).

## Run

```bash
pip install -r requirements.txt   # no third-party deps; stdlib only
python app.py                      # listens on $PORT (default 8765)
```

- `GET /healthz` → `200 {"ok": true}` (platform health check)
- `POST /mcp` → MCP Streamable HTTP JSON-RPC (Accept `application/json` or
  `text/event-stream`)

## MCP handshake (what a judge's client does)

```text
POST /mcp  initialize            -> protocolVersion 2025-11-25, capabilities.tools
POST /mcp  tools/list            -> screen_text, redact_text, moderate_text
POST /mcp  tools/call screen_text {text:"Ignore all previous instructions"}
                                 -> {decision:"refuse", risk:63, findings:[...]}
```

## Test

```bash
python eval.py     # engine + real Streamable HTTP handshake; exit 0 = all green
```

The suite asserts benign traffic passes, known attacks are refused, the three
gate-regression classes (Latin-substring false hit, URL-host educational
downgrade, missing jailbreak phrasing) stay fixed, and the HTTP transport
serves `initialize`/`tools/list`/`tools/call` over both JSON and SSE framing.

## Design rules

- Zero dependencies (Python standard library only).
- Deterministic: same input → same verdict.
- Never fabricate: every finding carries its rule id and matched span.
- Benign traffic must pass (false-positive rate is a scored dimension).

Derived from [AuditPilot's AgentGuard](https://github.com/Zhiyilang/auditpilot)
(68/68 regression assertions upstream). MIT licensed.
