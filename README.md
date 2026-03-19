# Zeek Detection POCs

Network threat detection proof-of-concepts using [Zeek](https://zeek.org/).

Each POC includes a Docker-based lab, custom Zeek detection scripts, and research documentation.

## POCs

| POC | Description | Detections |
|-----|-------------|------------|
| [weak_cipher](weak_cipher/) | Detect weak TLS/SSL cipher suites | RC4, DES, 3DES, no-PFS, deprecated TLS versions |
| [mcp_detect](mcp_detect/) | Detect MCP (Model Context Protocol) servers | MCP headers, JSON-RPC methods, unauthenticated servers, plaintext MCP |

## Prerequisites

- Docker + Docker Compose
- [Zeek](https://zeek.org/) (v6.0+)

## Quick Start

```bash
# Run weak cipher detection lab
cd weak_cipher && ./scripts/run-test.sh

# Run MCP server detection lab
cd mcp_detect && ./scripts/run-test.sh
```
