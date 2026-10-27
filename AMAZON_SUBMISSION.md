# AlexaGuard-MCP — Amazon Developer Hackathon 提交包（Devpost 复制即填）

> 赛事：Amazon Developer Hackathon 2026（Build, Ship, Shape）· **Alexa+ 赛道**
> 官方页：https://amazonappdev2026.devpost.com/ · 截止：**北京 10-24 03:00**（10-23 12:00 PDT）
> 仓：https://github.com/Zhiyilang/alexaguard-mcp （公开 / main / MIT，2026-10-21 实测 private:False）｜镜像（同代码，Gitee 匿名可复现 69/69）：https://gitee.com/ZhiYIlang/alexaguard-mcp
> 断言：**69/69 passed, 0 failed**（2026-10-21 实测 rc=0，wall 0.75s）
> 视频：`alexaguard_demo.mp4` **33.534s / 1280×720**（2026-10-21 实测 PASS，< 3min 合规）

## 为什么这条合规（官方 Alexa+ 要求逐字）

官方原文：*"Create a self-hosted MCP server (spec 2025-11-25 or later, Streamable HTTP)
or an Agent Skill."* —— 本仓就是自托管 MCP server，协议版本 **2025-11-25**，
传输 **Streamable HTTP**，纯 Python 标准库零依赖。官方另要求
*"repo needs to actually call your track's required technology in code"*：
`mcp_http.py` 是真的协议实现（握手 + 工具调用 + JSON/SSE 双模式），不是 README 提及。

## 📋 Devpost 表单字段（复制即填）

### ① 项目描述（必填）

> AlexaGuard-MCP wraps a 27-rule prompt-injection / PII safety engine (AgentGuard) as
> a self-hosted MCP server on the Alexa+ track (spec 2025-11-25, Streamable HTTP),
> built with the Python standard library only — zero dependencies. It exposes three
> tools over MCP: `screen_text` (full allow/refuse risk verdict), `redact_text` (PII
> redaction), and `moderate_text` (harm-category flagging). Any Alexa+ agent can call
> it to sanitize untrusted text before it reaches the model. Shipped with a 69/69
> assertion eval suite, a reproducible HTTP-handshake demo, and a one-command deploy.

### ② 产品反馈（必填；按"自建 stdlib 实现"口径，不暗示用了 Amazon SDK）

> I implemented a self-hosted MCP server to the Alexa+ spec (2025-11-25, Streamable
> HTTP) using only the Python standard library — no Amazon SDK needed. The spec is
> clean and the JSON/SSE content negotiation works as documented once the response
> Content-Type is set correctly. Suggested improvement: a typed tool-result schema in
> the initialize capabilities, plus clearer guidance on when to emit text/event-stream
> vs application/json.

### ③ Friction Log（可选，+10% 评分 bonus；据真实开发摩擦填）

- **任务**：让 `mcp_demo.py` 以 Streamable HTTP 完成 MCP 握手并解析工具结果。
- **期望 vs 实际**：初次给 JSON 响应也带了 `text/event-stream` 头 → 客户端按 SSE 帧解析、JSON 解析失败；期望握手与工具调用走同一 HTTP 连接即可。
- **严重度**：中（阻塞 demo，约 30 分钟定位）。
- **变通**：仅对真正的 SSE 响应设 `text/event-stream`，JSON 响应固定 `application/json`；SSE keep-alive 帧在响应结束后主动关连接，避免挂起。
- **建议**：Alexa+ MCP 预览文档补一条「Content-Type 按响应体类型二选一」的明确示例，并说明 SSE 终止条件。

### ④ GitHub 仓链接

`https://github.com/Zhiyilang/alexaguard-mcp`（About 区已显示 MIT license —— 官方要求 OSS license 在 About 可见）

## 🎬 视频上传（标题/描述/标签）

**文件**：仓内 `alexaguard_demo.mp4`（33.534s / 1280×720 / 290KB）
**真跑内容**（视频四段，均为真实命令实录，非摆拍）：
1. `python eval.py` → 69/69 全绿
2. `python mcp_demo.py` → 真实 Streamable HTTP 握手（protocolVersion 2025-11-25 + 3 工具）
3. `screen_text` 拒绝一次提示注入（decision: refuse / risk: 63）
4. `redact_text` 脱敏 PII

**标题（二选一）**：
- A. `AlexaGuard-MCP — Sanitize Untrusted Text Before It Reaches the Model (Self-Hosted MCP for Alexa+)`
- B. `I Built a Prompt-Injection Firewall as an MCP Server (Amazon Alexa+ Hackathon)`

**描述（直接粘贴）**：

```
AlexaGuard-MCP is a self-hosted MCP server (Model Context Protocol, spec
2025-11-25, Streamable HTTP) that screens, redacts, and moderates untrusted
text before any Alexa+ agent sends it to the model.

Built with the Python standard library only — zero dependencies.

What it does (every finding carries evidence):
- screen_text: full allow/refuse verdict with a 0-100 risk score across 27
  rules (credential exposure, deserialization, filesystem, host, network,
  privilege, process, resource categories)
- redact_text: PII redaction (emails, phone numbers, card-shaped numbers)
- moderate_text: harm-category flagging

The demo runs real commands: the 69/69 assertion eval suite, a real MCP
handshake over Streamable HTTP, a refused prompt injection, and a PII
redaction — no mockups.

Repo: https://github.com/Zhiyilang/alexaguard-mcp
```

**标签**：`MCP` `Model Context Protocol` `Alexa+` `Amazon Developer Hackathon` `prompt injection` `AI safety` `Python` `zero dependencies`

**上传设置**：Visibility = **Public**（官方要求 YouTube/Vimeo 公开可看）

## ⏱️ 提交顺序（双提交打法，总计约 40 分钟）

1. 注册 Devpost（https://amazonappdev2026.devpost.com/ → Register，免费）
2. **提交 #1 = 本仓 alexaguard-mcp**（主池 $138k）：按上面四字段填，传本视频
3. **提交 #2 = receiptbox**（$25k 专项）：文案在 `receiptbox/AMAZON_SUBMISSION.md`，视频用 `receiptbox/receiptbox_demo.mp4`（27.9s 实测 PASS），YouTube 包在根目录 `AMAZON_YOUTUBE_PACK.md`
4. 两个提交都填 Friction Log（各 +10% bonus）
5. 别卡 10-24 03:00，10-23 白天交完留缓冲
