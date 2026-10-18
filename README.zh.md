# AgentGuard MCP

一个**零依赖、自托管的 MCP 服务器**，把 AgentGuard 确定性安全引擎封装成
符合 **Alexa+ 赛道**要求的 Agent Skill。它对 Agent 输入、工具参数、检索
文档做提示词注入 / 越狱 / 提权 / 工具劫持 / 数据外泄 / PII 检测，返回结构化
判定——**无模型调用、无网络、对正常流量零误报**。

为 **Amazon Developer Hackathon 2026 — Alexa+ 赛道**（Build, Ship, Shape）
而建。服务器使用 **MCP Streamable HTTP 传输，协议 `2025-11-25`**，正是该
赛道要求的规格。

## 为什么

AgentGuard 最初为第七届中国人工智能大赛「智能体安全防护挑战赛」构建，针对
八月对抗样本集上观察到的五类真实误判做了标定。它确定性强、完全离线，任何
Agent 都能把它当作护栏调用，不引入额外延迟、成本或模型。

同一套引擎已在四条竞赛线复用（中国AI安全赛 / 迪拜 Create AI Agents /
Gemma 论文 / 松江AI游戏），本 MCP 服务器是其共享、可复用的安全接口面。

## 工具

| 工具 | 输入 | 输出 |
|------|------|------|
| `screen_text` | `{text}` | `{decision, risk, findings[], reasons, pii, redacted}` 完整判定 |
| `redact_text` | `{text}` | `{redacted, pii_redacted}` PII 脱敏副本 |
| `moderate_text` | `{text}` | `{flagged, categories{}}` 类 OpenAI moderations 的标记向量 |

`decision` 取值 `allow` / `refuse` / `sanitize`。用户自己消息里的 PII 会被
脱敏并记录，**绝不拒绝**（输入含 PII 不是攻击）。

## 运行

```bash
python app.py     # 监听 $PORT（默认 8765）
```

- `GET /healthz` → `200 {"ok": true}`（平台健康检查）
- `POST /mcp` → MCP Streamable HTTP JSON-RPC（Accept `application/json` 或
  `text/event-stream`）

## 测试

```bash
python eval.py    # 引擎 + 真实 Streamable HTTP 握手；exit 0 = 全绿
```

由 [AuditPilot 的 AgentGuard](https://github.com/Zhiyilang/auditpilot)
派生（本仓离线测试套件 **69/69** 引擎+传输断言，移植自上游回归库）。MIT 许可。
