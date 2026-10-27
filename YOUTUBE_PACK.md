# 📺 YouTube 上传包 · AlexaGuard-MCP（复制即用）

> 视频文件：`alexaguard-mcp/alexaguard_demo.mp4`（33.534s / 1280×720 / 290KB，实测 < 3min 合规）
> 用途：Amazon Developer Hackathon Devpost 提交必填的公开演示视频链接。

## Title（标题，复制）

```
AlexaGuard-MCP — 27-rule prompt-injection & PII safety engine as a self-hosted MCP server (Alexa+ track)
```

## Description（描述，复制）

```
AlexaGuard-MCP wraps a 27-rule prompt-injection / PII safety engine (AgentGuard) as a
self-hosted MCP server on the Amazon Alexa+ track (MCP spec 2025-11-25, Streamable HTTP),
built with the Python standard library only — zero dependencies.

It exposes three tools over MCP:
  • screen_text  — full allow/refuse risk verdict on any text
  • redact_text  — PII redaction before text leaves the device
  • moderate_text— harm-category flagging

Any Alexa+ agent (or Claude Desktop / self-built agent) can call it. This 33-second demo
runs the real engine: a benign prompt is served, a prompt-injection attempt is refused
with a cited rule, and PII is redacted — all deterministic, all offline, no API keys.

Repo (public, MIT): https://github.com/Zhiyilang/alexaguard-mcp
Built for: Build, Ship, Shape — Amazon Developer Hackathon 2026 (Alexa+ track)

#Alexa #MCP #ModelContextProtocol #AIagents #promptinjection #PII #opensource #Python
```

## Tags（标签，复制）

```
Alexa, Alexa+, MCP, Model Context Protocol, AI agent, prompt injection, PII, redaction,
safety, LLM security, Python, zero-dependency, open source, hackathon, Amazon Developer Hackathon 2026
```

## 上传注意

- 可见性设 **Public**（官方规则逐字要求 demo video 必须 public 可看；评委凭链接可访问）。
- 上传后把视频 URL 填进 `AMAZON_SUBMISSION.md` 的「视频链接」字段，再整份粘进 Devpost。
