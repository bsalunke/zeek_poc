"""
Minimal MCP server for Zeek detection testing.

Implements both Streamable HTTP and Legacy SSE transports so Zeek
can observe real MCP protocol traffic on the wire.

Runs on port 3000 (HTTP — intentionally no TLS for pcap inspection).
"""

import json
import uuid
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

SERVER_INFO = {
    "name": "test-mcp-server",
    "version": "1.0.0",
}

PROTOCOL_VERSION = "2025-06-18"

# Simulated tools the server exposes
TOOLS = [
    {
        "name": "read_file",
        "description": "Read contents of a file from the filesystem",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "run_query",
        "description": "Execute a database query",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sql": {"type": "string", "description": "SQL query to execute"},
            },
            "required": ["sql"],
        },
    },
    {
        "name": "send_email",
        "description": "Send an email message",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
    },
]

RESOURCES = [
    {
        "uri": "file:///etc/config.json",
        "name": "Application Config",
        "mimeType": "application/json",
    },
    {
        "uri": "db://users/schema",
        "name": "Users Table Schema",
        "mimeType": "text/plain",
    },
]

PROMPTS = [
    {
        "name": "summarize",
        "description": "Summarize the given text",
        "arguments": [
            {"name": "text", "description": "Text to summarize", "required": True},
        ],
    },
]


class MCPSession:
    """Track an MCP session."""
    def __init__(self):
        self.session_id = str(uuid.uuid4())
        self.initialized = False


# Active sessions
sessions: dict[str, MCPSession] = {}


def make_jsonrpc_response(req_id, result):
    return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result})


def make_jsonrpc_error(req_id, code, message):
    return json.dumps({
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": code, "message": message},
    })


def handle_jsonrpc(body: dict, session: Optional[MCPSession]) -> tuple[str, Optional[MCPSession]]:
    """Process a JSON-RPC request and return (response_json, session)."""
    method = body.get("method", "")
    req_id = body.get("id")
    params = body.get("params", {})

    if method == "initialize":
        session = MCPSession()
        sessions[session.session_id] = session
        result = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": {"listChanged": True},
                "resources": {"subscribe": True, "listChanged": True},
                "prompts": {"listChanged": True},
            },
            "serverInfo": SERVER_INFO,
        }
        return make_jsonrpc_response(req_id, result), session

    if method == "notifications/initialized":
        if session:
            session.initialized = True
        return "", session  # No response for notifications

    if method == "ping":
        return make_jsonrpc_response(req_id, {}), session

    if method == "tools/list":
        return make_jsonrpc_response(req_id, {"tools": TOOLS}), session

    if method == "tools/call":
        tool_name = params.get("name", "unknown")
        return make_jsonrpc_response(req_id, {
            "content": [
                {"type": "text", "text": f"[simulated] Tool '{tool_name}' executed successfully"},
            ],
        }), session

    if method == "resources/list":
        return make_jsonrpc_response(req_id, {"resources": RESOURCES}), session

    if method == "resources/read":
        uri = params.get("uri", "")
        return make_jsonrpc_response(req_id, {
            "contents": [
                {"uri": uri, "mimeType": "text/plain", "text": f"[simulated] Content of {uri}"},
            ],
        }), session

    if method == "prompts/list":
        return make_jsonrpc_response(req_id, {"prompts": PROMPTS}), session

    if method == "prompts/get":
        return make_jsonrpc_response(req_id, {
            "description": "Summarize text",
            "messages": [
                {"role": "user", "content": {"type": "text", "text": "Summarize: " + params.get("arguments", {}).get("text", "")}},
            ],
        }), session

    if method == "logging/setLevel":
        return make_jsonrpc_response(req_id, {}), session

    if method == "completion/complete":
        return make_jsonrpc_response(req_id, {"completion": {"values": ["option1", "option2"]}}), session

    # Unknown method
    if req_id is not None:
        return make_jsonrpc_error(req_id, -32601, f"Method not found: {method}"), session
    return "", session  # Notification — no response


class MCPHandler(BaseHTTPRequestHandler):
    """HTTP handler implementing both Streamable HTTP and Legacy SSE transports."""

    def log_message(self, format, *args):
        print(f"[MCP] {self.client_address[0]} - {format % args}")

    def do_GET(self):
        """Handle GET requests — SSE streams."""
        if self.path == "/sse" or self.path.startswith("/sse?"):
            # Legacy SSE transport — send endpoint event
            session = MCPSession()
            sessions[session.session_id] = session

            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            # Send the endpoint event (legacy MCP fingerprint)
            endpoint_url = f"/messages?session_id={session.session_id}"
            self.wfile.write(f"event: endpoint\ndata: {endpoint_url}\n\n".encode())
            self.wfile.flush()

            # Keep connection open briefly for detection
            time.sleep(2)
            self.wfile.write(f": keepalive - {time.time()}\n\n".encode())
            self.wfile.flush()
            time.sleep(1)

        elif self.path == "/mcp":
            # Streamable HTTP GET — open SSE stream for server notifications
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()

            # Send a notification
            notification = json.dumps({
                "jsonrpc": "2.0",
                "method": "notifications/message",
                "params": {"level": "info", "data": "Server ready"},
            })
            self.wfile.write(f"event: message\ndata: {notification}\n\n".encode())
            self.wfile.flush()
            time.sleep(2)

        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode())

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        """Handle POST requests — JSON-RPC messages."""
        content_length = int(self.headers.get("Content-Length", 0))
        body_raw = self.rfile.read(content_length).decode("utf-8")

        try:
            body = json.loads(body_raw)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error": "Invalid JSON"}')
            return

        # Determine session
        session_id = self.headers.get("Mcp-Session-Id", "")
        session = sessions.get(session_id)

        # Also check query param for legacy transport
        if not session and "session_id=" in self.path:
            sid = self.path.split("session_id=")[-1].split("&")[0]
            session = sessions.get(sid)

        response_json, session = handle_jsonrpc(body, session)

        if not response_json:
            # Notification — 202 Accepted, no body
            self.send_response(202)
            if session:
                self.send_header("Mcp-Session-Id", session.session_id)
            self.end_headers()
            return

        # Determine if this is an initialize response
        method = body.get("method", "")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")

        # Add MCP-specific headers
        if session:
            self.send_header("Mcp-Session-Id", session.session_id)
        if method == "initialize" or session:
            self.send_header("MCP-Protocol-Version", PROTOCOL_VERSION)

        self.end_headers()
        self.wfile.write(response_json.encode())

    def do_DELETE(self):
        """Handle DELETE — session termination."""
        session_id = self.headers.get("Mcp-Session-Id", "")
        if session_id in sessions:
            del sessions[session_id]
            self.send_response(200)
        else:
            self.send_response(404)
        self.end_headers()


def main():
    host = "0.0.0.0"
    port = 3000
    server = HTTPServer((host, port), MCPHandler)
    print(f"[MCP] Test MCP server running on {host}:{port}")
    print(f"[MCP] Streamable HTTP endpoint: POST /mcp")
    print(f"[MCP] Legacy SSE endpoint:      GET  /sse")
    print(f"[MCP] Health check:             GET  /health")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[MCP] Shutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
