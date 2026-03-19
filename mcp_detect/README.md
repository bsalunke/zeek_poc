# MCP Server Detection Lab

Detect Model Context Protocol (MCP) servers on the network using Zeek.

## Architecture

```
┌─────────────────────────────────────────┐
│  Docker Network                         │
│                                         │
│  ┌────────────────┐  ┌──────────────┐   │
│  │ mcp-server     │  │ tester       │   │
│  │ Python HTTP    │  │ tcpdump+curl │   │
│  │ :3000          │  │ 16 tests     │   │
│  └────────────────┘  └──────────────┘   │
└─────────────────────────────────────────┘
         │ pcap
         ▼
  Zeek + detect-mcp-servers.zeek
         │
         ▼
  mcp_detect.log + notice.log
```

## Quick Start

```bash
# Prerequisites: Docker, Zeek
./scripts/run-test.sh
```

## What It Detects

| Signal | Confidence | Example |
|--------|-----------|---------|
| `Mcp-Session-Id` header | HIGH | MCP-specific HTTP header |
| `MCP-Protocol-Version` header | HIGH | Date-format version string |
| MCP JSON-RPC methods | HIGH | `tools/call`, `resources/read`, `initialize` |
| No Authorization header | HIGH | Unauthenticated MCP server |
| Plaintext HTTP | HIGH | MCP without TLS |
| Legacy SSE (`GET /sse`) | MEDIUM | Deprecated but common transport |
| High tool call volume | ALERT | >20 calls/5min from same IP |

## Files

```
mcp_detect/
├── zeek/
│   └── detect-mcp-servers.zeek   # Zeek detection script
├── mcp-server/
│   ├── server.py                 # Test MCP server (Python)
│   └── Dockerfile
├── scripts/
│   └── run-test.sh               # Automated test runner
├── docs/
│   └── MCP-SERVER-DETECTION.md   # Full research document
├── output/                       # Generated pcap + Zeek logs
├── docker-compose.yml
└── README.md
```

## Documentation

See [docs/MCP-SERVER-DETECTION.md](docs/MCP-SERVER-DETECTION.md) for full research including:
- MCP protocol wire format
- All detection signatures with specifications
- Security risks and CVEs
- Lab validation results
