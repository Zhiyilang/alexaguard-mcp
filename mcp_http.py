"""Streamable HTTP MCP server for AgentGuard.

Zero dependencies (Python standard library only). Exposes three tools over the
MCP **Streamable HTTP** transport (protocol 2025-11-25) so it satisfies the
Amazon Developer Hackathon "Alexa+ -> self-hosted MCP server" track rule
(spec 2025-11-25 or later, Streamable HTTP):

  screen_text    guard_text() -> structured decision / risk / findings
  redact_text    redact()      -> PII-masked copy of the text
  moderate_text  OpenAI-moderations-shaped flag vector (flagged + categories)

Transport notes (MCP Streamable HTTP, 2025-11-25):
  - Clients POST JSON-RPC to /mcp with Accept: application/json OR
    text/event-stream. We echo the negotiated framing back.
  - A session id is issued on `initialize` (Mcp-Session-Id header) and
    accepted on later calls (lenient: missing id still served).
  - GET /healthz -> 200 {"ok": true} for platform health checks.

Run:  python app.py            (listens on $PORT, default 8765)
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import agentguard

PROTOCOL_VERSION = "2025-11-25"
SERVER_NAME = "alexaguard"
SERVER_VERSION = "1.0.0"

SESSIONS: set[str] = set()

_MOD_CATS = [
    "injection", "jailbreak", "smuggling", "tool_coercion",
    "exfiltration", "prompt_echo", "privilege", "pii",
]


# --------------------------------------------------------------------------
# tool catalogue
# --------------------------------------------------------------------------

def _tools_list() -> list:
    return [
        {
            "name": "screen_text",
            "description": (
                "Screen a piece of text (agent input, tool argument, retrieved "
                "document) for prompt injection, jailbreak, privilege escalation, "
                "tool coercion, exfiltration and PII. Returns a structured verdict: "
                "decision (allow/refuse/sanitize), a 0-100 risk score, and every "
                "finding with its rule id and matched span. Runs fully offline, "
                "deterministic, no model call."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text to screen"},
                },
                "required": ["text"],
            },
        },
        {
            "name": "redact_text",
            "description": (
                "Return a copy of the text with every detected PII span (CN mobile, "
                "resident ID, bank card, email, landline) replaced by [REDACTED]. "
                "Use before logging or echoing user content."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text to redact"},
                },
                "required": ["text"],
            },
        },
        {
            "name": "moderate_text",
            "description": (
                "OpenAI-moderations-shaped flagging: flagged (bool) plus a fixed "
                "category vector (injection/jailbreak/smuggling/tool_coercion/"
                "exfiltration/prompt_echo/privilege/pii). flagged is True when the "
                "engine refuses or finds PII."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text to moderate"},
                },
                "required": ["text"],
            },
        },
    ]


# --------------------------------------------------------------------------
# tool dispatch
# --------------------------------------------------------------------------

def _call_tool(name: str, args: dict):
    text = args.get("text", "")
    if name == "screen_text":
        return agentguard.guard_text(text).to_dict()
    if name == "redact_text":
        redacted = agentguard.redact(text)
        n = redacted.count("[REDACTED]")
        return {"redacted": redacted, "pii_redacted": n}
    if name == "moderate_text":
        v = agentguard.guard_text(text)
        cats = {c: False for c in _MOD_CATS}
        for f in v.findings:
            if f.category in cats:
                cats[f.category] = True
        flagged = (v.decision == "refuse") or any(
            f.category == "pii" for f in v.findings
        )
        return {"flagged": bool(flagged), "categories": cats}
    return None


def _handle(msg: dict):
    """Return a JSON-RPC response dict, or None for notifications."""
    method = msg.get("method")
    msg_id = msg.get("id")

    if method == "initialize":
        params = msg.get("params") or {}
        requested = params.get("protocolVersion", PROTOCOL_VERSION)
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": requested
                if requested in ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
                else PROTOCOL_VERSION,
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "capabilities": {"tools": {}},
            },
        }
    if (method or "").startswith("notifications/"):
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": _tools_list()}}
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name", "")
        args = params.get("arguments") or {}
        try:
            payload = _call_tool(name, args)
        except Exception as exc:  # protocol-legal tool error
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": f"tool error: {exc}"}],
                    "isError": True,
                },
            }
        if payload is None:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32602, "message": f"unknown tool: {name}"},
            }
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}]
            },
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": f"method not found: {method}"},
    }


# --------------------------------------------------------------------------
# HTTP transport
# --------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "AgentGuardMCP/1.0"

    # silence default stderr logging noise
    def log_message(self, *args):  # noqa: D401
        pass

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    def _send_jsonrpc(self, body: dict, session_id: str | None) -> None:
        accept = self.headers.get("Accept", "")
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Mcp-Session-Id", session_id or "")
        self.send_header("Cache-Control", "no-store")
        if "text/event-stream" in accept:
            # SSE: one event for this request/response, then close the stream
            # so the client (urllib / MCP client) sees EOF and parses.
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"event: message\ndata: ")
            self.wfile.write(data)
            self.wfile.write(b"\n\n")
            self.wfile.flush()
            self.close_connection = True
        else:
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        if self.path.split("?")[0] in ("/healthz", "/healthz/"):
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.split("?")[0] == "/":
            body = (
                b"<html><body><h1>AgentGuard MCP</h1>"
                b"<p>Streamable HTTP MCP server (protocol 2025-11-25). "
                b"POST JSON-RPC to <code>/mcp</code>.</p></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path not in ("/mcp", "/mcp/"):
            self.send_response(404)
            self.end_headers()
            return
        msg = self._read_body()
        if not isinstance(msg, dict) or "method" not in msg:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"bad request"}}')
            return
        # session handling: reuse provided id, else mint one
        sid = self.headers.get("Mcp-Session-Id")
        if not sid:
            sid = uuid.uuid4().hex
            SESSIONS.add(sid)
        body = _handle(msg)
        if body is None:  # notification -> 202 Accepted, no body
            self.send_response(202)
            self.send_header("Mcp-Session-Id", sid)
            self.end_headers()
            return
        self._send_jsonrpc(body, sid)


def serve(port: int | None = None, host: str = "0.0.0.0") -> ThreadingHTTPServer:
    port = port or int(os.environ.get("PORT", "8765"))
    httpd = ThreadingHTTPServer((host, port), _Handler)
    return httpd


def main() -> int:
    port = int(os.environ.get("PORT", "8765"))
    httpd = serve(port)
    print(f"AgentGuard MCP (Streamable HTTP, {PROTOCOL_VERSION}) on :{port}/mcp", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
