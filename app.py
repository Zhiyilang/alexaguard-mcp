"""Entry point: serve AgentGuard MCP over Streamable HTTP on $PORT.

Reads PORT from the environment (Render / cloud platforms set it),
binds 0.0.0.0, defaults to 8765 for local runs. Zero dependencies.
"""

import os

import mcp_http


def main() -> int:
    port = int(os.environ.get("PORT", "8765"))
    httpd = mcp_http.serve(port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
