# MCP Server Detection via Network Traffic — Research & Reference

> **Date:** 2026-03-18
> **Purpose:** Detect MCP (Model Context Protocol) servers on the network using Zeek packet inspection.

---

## Executive Summary

This document covers research and validation of detecting MCP servers by inspecting HTTP traffic with Zeek. MCP uses HTTP with JSON-RPC 2.0 over two transports: **Streamable HTTP** (current) and **Legacy HTTP+SSE** (deprecated but widely deployed). A custom Zeek detection script (`detect-mcp-servers.zeek`) identifies MCP traffic via **7 detection signatures** across 3 confidence tiers.

**Key facts about MCP network detection:**
- MCP traffic is identifiable via **MCP-specific HTTP headers** (`Mcp-Session-Id`, `MCP-Protocol-Version`) — no other protocol uses these
- JSON-RPC method names like `tools/call`, `resources/read`, and `prompts/list` are unique to MCP
- The Legacy SSE transport emits a distinctive `event: endpoint` SSE event
- Zeek inspects HTTP headers and bodies **without requiring TLS decryption** (when traffic is plaintext HTTP)
- For TLS-encrypted MCP traffic, a TLS decryption proxy is needed

---

## Table of Contents

1. [What is MCP](#1-what-is-mcp)
2. [MCP Transport Mechanisms](#2-mcp-transport-mechanisms)
3. [Network Fingerprints — HTTP Headers](#3-network-fingerprints--http-headers)
4. [Network Fingerprints — JSON-RPC Methods](#4-network-fingerprints--json-rpc-methods)
5. [Network Fingerprints — URL Paths and SSE Patterns](#5-network-fingerprints--url-paths-and-sse-patterns)
6. [Detection Signatures](#6-detection-signatures)
7. [Security Risks of Exposed MCP Servers](#7-security-risks-of-exposed-mcp-servers)
8. [Lab Validation — Findings and Results](#8-lab-validation--findings-and-results)
9. [Detection Limitations](#9-detection-limitations)
10. [References](#10-references)

---

## 1. What is MCP

Model Context Protocol (MCP) is an open standard for connecting AI assistants (Claude, GPT, etc.) to external tools, data sources, and services. An MCP server exposes:

- **Tools** — executable functions (file read, DB query, API calls)
- **Resources** — data endpoints (files, database schemas, configs)
- **Prompts** — reusable prompt templates

MCP uses JSON-RPC 2.0 for message framing over HTTP transports. The protocol version is identified by date strings (e.g., `2025-06-18`).

### Why Detect MCP Servers on the Network?

| Concern | Risk |
|---------|------|
| Unauthenticated MCP servers | Anyone can enumerate tools and execute commands |
| Data exfiltration via `tools/call` | Attacker can read files, query databases, send emails |
| Tool poisoning | Malicious MCP servers inject prompt manipulation payloads |
| Shadow AI infrastructure | Unauthorized MCP servers exposing internal services |
| No TLS | MCP traffic in plaintext exposes tool calls and data |

---

## 2. MCP Transport Mechanisms

### 2a. Streamable HTTP (Current — Protocol >= 2025-03-26)

Single HTTP endpoint handles all communication:

```
Client                                Server
  |                                     |
  |-- POST /mcp ---------------------->|  JSON-RPC request
  |   Content-Type: application/json    |
  |   Accept: application/json,         |
  |           text/event-stream         |
  |   Mcp-Session-Id: <uuid>           |  ← MCP-specific header
  |   MCP-Protocol-Version: 2025-06-18 |  ← MCP-specific header
  |                                     |
  |<-- 200 OK -------------------------|  JSON-RPC response
  |   Content-Type: application/json    |
  |   Mcp-Session-Id: <uuid>           |  ← MCP-specific header
  |                                     |
  |-- GET /mcp ----------------------->|  Open SSE stream (optional)
  |<-- text/event-stream --------------|  Server notifications
  |                                     |
  |-- DELETE /mcp -------------------->|  Session termination
```

### 2b. Legacy HTTP+SSE (Protocol 2024-11-05 — Deprecated)

Dual-endpoint architecture, still widely deployed:

```
Client                                Server
  |                                     |
  |-- GET /sse ----------------------->|  Open SSE connection
  |<-- text/event-stream --------------|
  |   event: endpoint                  |  ← Legacy MCP fingerprint
  |   data: /messages?session_id=xxx   |
  |                                     |
  |-- POST /messages?session_id=xxx -->|  JSON-RPC messages
  |<-- event: message -----------------|  Responses via SSE
```

### 2c. stdio (Not Network-Observable)

Local subprocess communication via stdin/stdout. Produces **zero network traffic** — invisible to Zeek.

---

## 3. Network Fingerprints — HTTP Headers

### MCP-Specific Headers (Definitive — No Other Protocol Uses These)

| Header | Direction | Value | Meaning |
|--------|-----------|-------|---------|
| `Mcp-Session-Id` | Request & Response | UUID/JWT/hash | MCP session identifier |
| `MCP-Protocol-Version` | Request & Response | `2025-06-18`, `2025-03-26`, `2024-11-05` | MCP protocol version (date format) |

### Supporting Headers (Corroborative)

| Header | Value | Context |
|--------|-------|---------|
| `Content-Type` | `application/json` | All POST requests |
| `Accept` | `application/json, text/event-stream` | Streamable HTTP POSTs (MUST per spec) |
| `Accept` | `text/event-stream` | SSE GET requests |
| `Content-Type` | `text/event-stream` | SSE responses |
| `Authorization` | `Bearer <token>` | OAuth 2.1 (optional) |

---

## 4. Network Fingerprints — JSON-RPC Methods

All MCP messages use JSON-RPC 2.0 with a `"method"` field. These methods are unique to MCP:

### Client → Server Requests

| Method | Purpose | Detection Value |
|--------|---------|----------------|
| `initialize` | Session handshake with `protocolVersion` | **Highest** — contains protocol version |
| `tools/list` | Enumerate available tools | High — MCP-specific |
| `tools/call` | Execute a tool | **Critical** — command execution |
| `resources/list` | Enumerate data sources | High — MCP-specific |
| `resources/read` | Read a data source | High — data access |
| `prompts/list` | Enumerate prompt templates | High — MCP-specific |
| `prompts/get` | Retrieve a prompt | High — MCP-specific |
| `sampling/createMessage` | Request LLM completion | High — MCP-specific |
| `elicitation/create` | Request user input | High — MCP-specific |
| `completion/complete` | Argument autocompletion | Medium |
| `logging/setLevel` | Set server log level | Medium |
| `ping` | Keep-alive | Low (generic) |

### Notifications (No `id` field)

| Method | Direction | Purpose |
|--------|-----------|---------|
| `notifications/initialized` | Client → Server | Client ready |
| `notifications/tools/list_changed` | Server → Client | Tool list changed |
| `notifications/resources/list_changed` | Server → Client | Resource list changed |
| `notifications/resources/updated` | Server → Client | Resource updated |
| `notifications/prompts/list_changed` | Server → Client | Prompt list changed |
| `notifications/cancelled` | Both | Cancel request |
| `notifications/progress` | Both | Progress update |

---

## 5. Network Fingerprints — URL Paths and SSE Patterns

### Common MCP URL Paths

| Path | Transport | Usage |
|------|-----------|-------|
| `/mcp` | Streamable HTTP | Primary endpoint (spec default) |
| `/mcp/v1` | Streamable HTTP | Versioned variant |
| `/api/mcp` | Streamable HTTP | API-prefixed |
| `/sse` | Legacy SSE | SSE connection endpoint |
| `/messages` | Legacy SSE | JSON-RPC POST endpoint |
| `/message` | Legacy SSE | Alternate POST endpoint |

### SSE Event Types

| Event Type | Transport | Meaning |
|------------|-----------|---------|
| `event: endpoint` | **Legacy only** | Contains POST URL — strong MCP fingerprint |
| `event: message` | Both | JSON-RPC message payload |
| `: ping` | Both | Keep-alive comment |

---

## 6. Detection Signatures

The Zeek script implements 7 detection signatures across 3 confidence tiers:

### Tier 1 — HIGH Confidence (Definitive MCP)

| # | Signature | Trigger | Notice Type |
|---|-----------|---------|-------------|
| 1 | `Mcp-Session-Id` header | HTTP header `Mcp-Session-Id` in request or response | `MCP_Server_Detected` |
| 2 | `MCP-Protocol-Version` header | HTTP header matching date pattern `YYYY-MM-DD` | `MCP_Server_Detected` |
| 3 | MCP JSON-RPC method | Body contains `"method":"initialize"` with `protocolVersion` | `MCP_Initialization_Observed` |
| 4 | Tool execution | `tools/call`, `sampling/createMessage`, or `elicitation/create` | `MCP_Tool_Call_Observed` |
| 5 | No authentication | MCP initialize without `Authorization` header | `MCP_No_Auth_Detected` |
| 6 | No TLS | MCP traffic on non-443 port | `MCP_No_TLS_Detected` |

### Tier 2 — MEDIUM Confidence (Probable MCP)

| # | Signature | Trigger | Notice Type |
|---|-----------|---------|-------------|
| 7 | Legacy SSE transport | `GET /sse` returning `text/event-stream`, or `event: endpoint` in SSE stream | `MCP_Legacy_Transport_Detected` |

### Additional Alerts

| Alert | Trigger | Notice Type |
|-------|---------|-------------|
| High volume tool calls | >20 `tools/call` from same source IP in 5 minutes | `MCP_High_Tool_Call_Volume` |

### Custom Log: `mcp_detect.log`

| Field | Type | Description |
|-------|------|-------------|
| `ts` | time | Timestamp |
| `uid` | string | Connection UID |
| `orig_h` / `orig_p` | addr/port | Client |
| `resp_h` / `resp_p` | addr/port | Server |
| `method` | string | HTTP method (GET/POST/DELETE) |
| `uri` | string | Request URI |
| `mcp_session_id` | string | MCP session ID if present |
| `mcp_proto_ver` | string | MCP protocol version if present |
| `jsonrpc_method` | string | JSON-RPC method name |
| `detection_tier` | string | HIGH / MEDIUM |
| `reason` | string | Human-readable detection reason |
| `has_auth` | bool | Whether Authorization header was present |
| `has_tls` | bool | Whether connection was on port 443 |
| `server_name` | string | MCP server name from initialize response |

---

## 7. Security Risks of Exposed MCP Servers

### Known Vulnerabilities

| CVE | Severity | Attack |
|-----|----------|--------|
| CVE-2025-6514 | Critical | `mcp-remote` command injection via crafted OAuth endpoint |
| CVE-2025-49596 | Critical | MCP Inspector RCE via unauthenticated proxy |
| CVE-2025-53109/53110 | High | Filesystem MCP sandbox escape via symlinks |
| CVE-2025-53967 | High | Figma MCP command injection |

### Attack Scenarios Detectable by Zeek

1. **Reconnaissance**: Attacker calls `tools/list` + `resources/list` to enumerate capabilities
2. **Data exfiltration**: `tools/call` with `read_file` or `run_query` to extract data
3. **Lateral movement**: `tools/call` to connected services (email, APIs, databases)
4. **Tool poisoning**: Malicious server returns prompt injection in `tools/list` descriptions
5. **Unauthenticated access**: `initialize` without `Authorization` header on exposed server

---

## 8. Lab Validation — Findings and Results

### Lab Architecture

```
┌─────────────────────────────────────────────┐
│  Docker Network: mcp-test-net               │
│                                             │
│  ┌──────────────────┐  ┌────────────────┐   │
│  │ mcp-server       │  │ tester         │   │
│  │ Python HTTP      │  │ netshoot       │   │
│  │ Port 3000        │  │ tcpdump + curl │   │
│  │                  │  │                │   │
│  │ POST /mcp        │  │ 16 test cases  │   │
│  │ GET  /sse        │  │                │   │
│  │ POST /messages   │  │                │   │
│  └──────────────────┘  └────────────────┘   │
│                                             │
└─────────────────────────────────────────────┘
         │ traffic captured via tcpdump
         ▼
┌──────────────────┐
│ Zeek Analysis    │
│ detect-mcp-      │
│ servers.zeek     │
└──────────────────┘
```

### Test Matrix

| # | Test | Method | Expected Detection |
|---|------|--------|--------------------|
| 1 | Initialize (Streamable HTTP) | `POST /mcp` | MCP_Initialization_Observed + MCP_No_Auth + MCP_No_TLS |
| 2 | notifications/initialized | `POST /mcp` + `Mcp-Session-Id` header | MCP_Server_Detected (header) |
| 3 | tools/list | `POST /mcp` | MCP JSON-RPC method |
| 4 | tools/call (read_file) | `POST /mcp` | MCP_Tool_Call_Observed |
| 5 | tools/call (run_query) | `POST /mcp` | MCP_Tool_Call_Observed |
| 6 | tools/call (send_email) | `POST /mcp` | MCP_Tool_Call_Observed |
| 7 | resources/list | `POST /mcp` | MCP JSON-RPC method |
| 8 | resources/read | `POST /mcp` | MCP JSON-RPC method |
| 9 | prompts/list | `POST /mcp` | MCP JSON-RPC method |
| 10 | prompts/get | `POST /mcp` | MCP JSON-RPC method |
| 11 | ping | `POST /mcp` | MCP JSON-RPC method |
| 12 | Legacy SSE | `GET /sse` | MCP_Legacy_Transport_Detected |
| 13 | Legacy POST /messages | `POST /messages` | MCP_Initialization_Observed |
| 14 | Rapid tool calls (×8) | `POST /mcp` | MCP_Tool_Call_Observed (volume) |
| 15 | Session DELETE | `DELETE /mcp` | Header detection |
| 16 | No-auth initialize | `POST /mcp` (no auth) | MCP_No_Auth_Detected |

---

## 9. Detection Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| TLS-encrypted MCP traffic | Cannot inspect headers/body without decryption | Deploy TLS inspection proxy (corporate environments) |
| stdio transport | Zero network traffic — completely invisible | Host-based detection (process monitoring) |
| Custom MCP paths | Non-standard paths miss Tier 2 path-based detection | Tier 1 header/body detection still works |
| High-volume environments | JSON body parsing adds CPU overhead | Use BPF filter to target known MCP ports |
| Encrypted Client Hello (ECH) | Cannot even see SNI | Block ECH or use TLS proxy |

---

## 10. References

- [MCP Specification (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18)
- [MCP Transports — Streamable HTTP](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)
- [MCP Legacy Transports (2024-11-05)](https://modelcontextprotocol.io/legacy/concepts/transports)
- [MCP Security Risks — Pillar Security](https://www.pillar.security/blog/the-security-risks-of-model-context-protocol-mcp)
- [MCP Attack Vectors — Unit42 (Palo Alto Networks)](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- [Timeline of MCP Security Breaches — AuthZed](https://authzed.com/blog/timeline-mcp-breaches)
- [MCP Security Vulnerabilities — Practical DevSecOps](https://www.practical-devsecops.com/mcp-security-vulnerabilities/)
- [Zeek HTTP Analysis Documentation](https://docs.zeek.org/en/current/scripts/base/protocols/http/main.zeek.html)
