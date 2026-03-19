##! MCP (Model Context Protocol) Server Detection via Network Traffic
##!
##! Detects MCP servers by inspecting HTTP headers and JSON-RPC payloads.
##! MCP uses HTTP+SSE or Streamable HTTP transports with JSON-RPC 2.0 messages.
##!
##! Detection Tiers:
##!   HIGH   — MCP-specific headers (Mcp-Session-Id, MCP-Protocol-Version)
##!   HIGH   — MCP JSON-RPC methods (initialize w/ protocolVersion, tools/list, etc.)
##!   MEDIUM — Legacy SSE patterns (GET /sse, event: endpoint)
##!   LOW    — Heuristic path + header combos (/mcp, /messages with JSON-RPC)
##!
##! Author: Security Research Lab
##! Date:   2026-03-18

@load base/protocols/http
@load base/frameworks/notice

module MCPDetect;

export {
    ## Notice types for MCP detection
    redef enum Notice::Type += {
        ## High-confidence MCP server detected via definitive headers
        MCP_Server_Detected,
        ## MCP initialization handshake observed
        MCP_Initialization_Observed,
        ## MCP tool call observed — potential command execution
        MCP_Tool_Call_Observed,
        ## Unauthenticated MCP server — no Authorization header
        MCP_No_Auth_Detected,
        ## MCP over plaintext HTTP — no TLS
        MCP_No_TLS_Detected,
        ## Legacy SSE-based MCP transport detected
        MCP_Legacy_Transport_Detected,
        ## High volume of MCP tool calls — possible exfiltration
        MCP_High_Tool_Call_Volume,
    };

    ## Custom log stream for MCP detections
    redef enum Log::ID += { LOG };

    ## Record for mcp_detect.log
    type Info: record {
        ts:               time    &log;
        uid:              string  &log;
        orig_h:           addr    &log;
        orig_p:           port    &log;
        resp_h:           addr    &log;
        resp_p:           port    &log;
        method:           string  &log &default="";
        uri:              string  &log &default="";
        mcp_session_id:   string  &log &default="";
        mcp_proto_ver:    string  &log &default="";
        jsonrpc_method:   string  &log &default="";
        detection_tier:   string  &log &default="";
        reason:           string  &log &default="";
        has_auth:         bool    &log &default=F;
        has_tls:          bool    &log &default=F;
        server_name:      string  &log &default="";
        server_version:   string  &log &default="";
    };

    ## Tracking state per HTTP connection
    type ConnState: record {
        uid:              string  &default="";
        method:           string  &default="";
        uri:              string  &default="";
        content_type:     string  &default="";
        accept_hdr:       string  &default="";
        mcp_session_id:   string  &default="";
        mcp_proto_ver:    string  &default="";
        has_auth:         bool    &default=F;
        is_sse:           bool    &default=F;
        resp_content_type: string &default="";
        body_data:        string  &default="";
    };

    ## Paths commonly used by MCP servers
    const mcp_path_pattern = /^\/(mcp|sse|messages?)(\/|$|\?)/ &redef;

    ## MCP-specific JSON-RPC methods (definitive identifiers)
    const mcp_methods: set[string] = {
        "initialize",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/read",
        "resources/subscribe",
        "resources/unsubscribe",
        "resources/templates/list",
        "prompts/list",
        "prompts/get",
        "sampling/createMessage",
        "elicitation/create",
        "logging/setLevel",
        "completion/complete",
        "notifications/initialized",
        "notifications/cancelled",
        "notifications/progress",
        "notifications/tools/list_changed",
        "notifications/resources/list_changed",
        "notifications/resources/updated",
        "notifications/prompts/list_changed",
        "notifications/roots/list_changed",
        "notifications/message",
        "roots/list",
        "ping",
    } &redef;

    ## Methods that indicate active tool execution
    const tool_exec_methods: set[string] = {
        "tools/call",
        "sampling/createMessage",
        "elicitation/create",
    } &redef;

    ## MCP protocol version pattern (date format: YYYY-MM-DD)
    const proto_ver_pattern = /20[0-9][0-9]-[01][0-9]-[0-3][0-9]/;

    ## Threshold for high tool call volume alert (per source IP per interval)
    const tool_call_threshold: count = 20 &redef;

    ## Interval for tool call volume tracking
    const tool_call_interval = 5min &redef;
}

## Per-connection tracking table
global conn_state: table[string] of ConnState;

## Tool call volume tracking: [orig_h] -> count
global tool_call_counts: table[addr] of count &default=0;

## Timer for resetting tool call counts
global last_reset: time = network_time();

event zeek_init()
    {
    Log::create_stream(MCPDetect::LOG,
        [$columns=Info, $path="mcp_detect"]);
    }

## Extract MCP-specific method from JSON-RPC body (simple pattern match)
function extract_jsonrpc_method(body: string): string
    {
    # Match "method":"<value>" or "method": "<value>"
    local pat = /\"method\"\s*:\s*\"([^\"]+)\"/;
    local parts = split_string(body, pat);

    # Try a more direct approach — find the method value
    local idx = strstr(body, "\"method\"");
    if ( idx == 0 )
        return "";

    local after_key = sub_bytes(body, idx + 8, |body|);
    # Skip whitespace and colon
    local colon_pos = strstr(after_key, "\"");
    if ( colon_pos == 0 )
        return "";

    local after_quote = sub_bytes(after_key, colon_pos + 1, |after_key|);
    local end_quote = strstr(after_quote, "\"");
    if ( end_quote == 0 )
        return "";

    return sub_bytes(after_quote, 0, end_quote);
    }

## Extract protocolVersion from JSON body
function extract_protocol_version(body: string): string
    {
    local idx = strstr(body, "\"protocolVersion\"");
    if ( idx == 0 )
        return "";

    local after_key = sub_bytes(body, idx + 18, |body|);
    local quote_start = strstr(after_key, "\"");
    if ( quote_start == 0 )
        return "";

    local after_quote = sub_bytes(after_key, quote_start + 1, |after_key|);
    local end_quote = strstr(after_quote, "\"");
    if ( end_quote == 0 )
        return "";

    return sub_bytes(after_quote, 0, end_quote);
    }

## Extract serverInfo name from JSON body
function extract_server_name(body: string): string
    {
    local idx = strstr(body, "\"serverInfo\"");
    if ( idx == 0 )
        return "";

    local block = sub_bytes(body, idx, idx + 200 < |body| ? 200 : |body| - idx);
    local name_idx = strstr(block, "\"name\"");
    if ( name_idx == 0 )
        return "";

    local after_name = sub_bytes(block, name_idx + 6, |block|);
    local q1 = strstr(after_name, "\"");
    if ( q1 == 0 )
        return "";

    local after_q1 = sub_bytes(after_name, q1 + 1, |after_name|);
    local q2 = strstr(after_q1, "\"");
    if ( q2 == 0 )
        return "";

    return sub_bytes(after_q1, 0, q2);
    }

## Log an MCP detection
function log_mcp_detection(c: connection, cs: ConnState,
                            tier: string, reason: string,
                            jsonrpc_method: string)
    {
    local info = Info(
        $ts = network_time(),
        $uid = c$uid,
        $orig_h = c$id$orig_h,
        $orig_p = c$id$orig_p,
        $resp_h = c$id$resp_h,
        $resp_p = c$id$resp_p,
        $method = cs$method,
        $uri = cs$uri,
        $mcp_session_id = cs$mcp_session_id,
        $mcp_proto_ver = cs$mcp_proto_ver,
        $jsonrpc_method = jsonrpc_method,
        $detection_tier = tier,
        $reason = reason,
        $has_auth = cs$has_auth,
        $has_tls = (c$id$resp_p == 443/tcp)
    );

    Log::write(MCPDetect::LOG, info);
    }

## Track HTTP request method and URI
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    local uid = c$uid;
    if ( uid !in conn_state )
        conn_state[uid] = ConnState($uid=uid);

    conn_state[uid]$method = method;
    conn_state[uid]$uri = unescaped_URI;
    }

## Inspect HTTP headers for MCP fingerprints
event http_header(c: connection, is_orig: bool, original_name: string,
                  name: string, value: string)
    {
    local uid = c$uid;
    if ( uid !in conn_state )
        conn_state[uid] = ConnState($uid=uid);

    local cs = conn_state[uid];

    if ( is_orig )
        {
        # Request headers (client -> server)
        if ( name == "CONTENT-TYPE" )
            cs$content_type = value;
        else if ( name == "ACCEPT" )
            cs$accept_hdr = value;
        else if ( name == "AUTHORIZATION" )
            cs$has_auth = T;
        else if ( name == "MCP-SESSION-ID" )
            {
            cs$mcp_session_id = value;
            # Tier 1: Definitive MCP header
            log_mcp_detection(c, cs, "HIGH",
                "MCP-specific header: Mcp-Session-Id present in request", "");
            NOTICE([
                $note=MCP_Server_Detected,
                $conn=c,
                $msg=fmt("[HIGH] MCP session header detected: Mcp-Session-Id=%s",
                         value),
                $sub=cs$uri,
                $suppress_for=30min
            ]);
            }
        else if ( name == "MCP-PROTOCOL-VERSION" )
            {
            cs$mcp_proto_ver = value;
            # Tier 1: Definitive MCP header
            log_mcp_detection(c, cs, "HIGH",
                fmt("MCP-specific header: MCP-Protocol-Version=%s", value), "");
            NOTICE([
                $note=MCP_Server_Detected,
                $conn=c,
                $msg=fmt("[HIGH] MCP protocol version header: %s", value),
                $sub=cs$uri,
                $suppress_for=30min
            ]);
            }
        }
    else
        {
        # Response headers (server -> client)
        if ( name == "CONTENT-TYPE" )
            {
            cs$resp_content_type = value;
            if ( /text\/event-stream/ in value )
                cs$is_sse = T;
            }
        else if ( name == "MCP-SESSION-ID" )
            {
            cs$mcp_session_id = value;
            log_mcp_detection(c, cs, "HIGH",
                "MCP-specific header: Mcp-Session-Id in response (server confirmed)", "");
            NOTICE([
                $note=MCP_Server_Detected,
                $conn=c,
                $msg=fmt("[HIGH] MCP server responded with Mcp-Session-Id=%s", value),
                $sub=cs$uri,
                $suppress_for=30min
            ]);
            }
        else if ( name == "MCP-PROTOCOL-VERSION" )
            {
            cs$mcp_proto_ver = value;
            }
        }

    conn_state[uid] = cs;
    }

## Inspect HTTP entity (body) data for JSON-RPC MCP methods
event http_entity_data(c: connection, is_orig: bool, length: count,
                       data: string)
    {
    local uid = c$uid;
    if ( uid !in conn_state )
        return;

    local cs = conn_state[uid];

    # Accumulate body data (up to a reasonable limit for parsing)
    if ( |cs$body_data| < 4096 )
        cs$body_data += data;

    local body = cs$body_data;

    # Only parse if it looks like JSON-RPC
    if ( "jsonrpc" !in body )
        {
        conn_state[uid] = cs;
        return;
        }

    local rpc_method = extract_jsonrpc_method(body);
    if ( rpc_method == "" )
        {
        conn_state[uid] = cs;
        return;
        }

    # Check if this is an MCP-specific method
    if ( rpc_method in mcp_methods )
        {
        local tier = "HIGH";
        local reason = fmt("MCP JSON-RPC method: %s", rpc_method);

        # Initialize is the strongest signal — extract protocol version
        if ( rpc_method == "initialize" )
            {
            local proto_ver = extract_protocol_version(body);
            if ( proto_ver != "" )
                cs$mcp_proto_ver = proto_ver;

            local srv_name = extract_server_name(body);

            log_mcp_detection(c, cs, tier,
                fmt("MCP initialization: protocolVersion=%s", proto_ver),
                rpc_method);

            NOTICE([
                $note=MCP_Initialization_Observed,
                $conn=c,
                $msg=fmt("[HIGH] MCP initialize handshake: protocolVersion=%s server=%s",
                         proto_ver, srv_name),
                $sub=rpc_method,
                $suppress_for=30min
            ]);

            # Check for missing auth
            if ( ! cs$has_auth )
                {
                NOTICE([
                    $note=MCP_No_Auth_Detected,
                    $conn=c,
                    $msg=fmt("[HIGH] MCP server at %s:%s has NO authorization header",
                             c$id$resp_h, c$id$resp_p),
                    $sub="No Authorization header in MCP initialize",
                    $suppress_for=30min
                ]);
                }

            # Check for plaintext HTTP
            if ( c$id$resp_p != 443/tcp )
                {
                NOTICE([
                    $note=MCP_No_TLS_Detected,
                    $conn=c,
                    $msg=fmt("[HIGH] MCP traffic over plaintext HTTP to %s:%s",
                             c$id$resp_h, c$id$resp_p),
                    $sub="MCP without TLS encryption",
                    $suppress_for=30min
                ]);
                }
            }

        # Tool calls — track for volume alerts
        else if ( rpc_method in tool_exec_methods )
            {
            log_mcp_detection(c, cs, tier,
                fmt("MCP tool execution: %s", rpc_method), rpc_method);

            NOTICE([
                $note=MCP_Tool_Call_Observed,
                $conn=c,
                $msg=fmt("[MEDIUM] MCP tool call observed: %s from %s",
                         rpc_method, c$id$orig_h),
                $sub=rpc_method,
                $suppress_for=5min
            ]);

            # Volume tracking
            local src = c$id$orig_h;
            if ( network_time() - last_reset > tool_call_interval )
                {
                tool_call_counts = table();
                last_reset = network_time();
                }
            if ( src !in tool_call_counts )
                tool_call_counts[src] = 0;
            tool_call_counts[src] += 1;

            if ( tool_call_counts[src] == tool_call_threshold )
                {
                NOTICE([
                    $note=MCP_High_Tool_Call_Volume,
                    $conn=c,
                    $msg=fmt("[HIGH] High MCP tool call volume from %s: %d calls in %s",
                             src, tool_call_counts[src], tool_call_interval),
                    $sub=fmt("%d tool calls", tool_call_counts[src]),
                    $suppress_for=30min
                ]);
                }
            }
        else
            {
            # Other MCP methods (tools/list, resources/read, etc.)
            log_mcp_detection(c, cs, tier, reason, rpc_method);
            }
        }

    # Check for legacy SSE endpoint event
    if ( ! is_orig && "event: endpoint" in body )
        {
        log_mcp_detection(c, cs, "MEDIUM",
            "Legacy MCP SSE transport: 'event: endpoint' detected", "");
        NOTICE([
            $note=MCP_Legacy_Transport_Detected,
            $conn=c,
            $msg=fmt("[MEDIUM] Legacy MCP SSE transport detected at %s:%s (endpoint event in SSE stream)",
                     c$id$resp_h, c$id$resp_p),
            $sub="event: endpoint (legacy MCP SSE)",
            $suppress_for=30min
        ]);
        }

    conn_state[uid] = cs;
    }

## Check for MCP path patterns on HTTP reply
event http_reply(c: connection, version: string, code: count, reason: string)
    {
    local uid = c$uid;
    if ( uid !in conn_state )
        return;

    local cs = conn_state[uid];

    # Tier 2: GET /sse returning text/event-stream (legacy MCP)
    if ( cs$method == "GET" && /\/sse/ in cs$uri && cs$is_sse )
        {
        log_mcp_detection(c, cs, "MEDIUM",
            "Legacy MCP: GET /sse returning text/event-stream", "");
        NOTICE([
            $note=MCP_Legacy_Transport_Detected,
            $conn=c,
            $msg=fmt("[MEDIUM] Possible legacy MCP SSE endpoint: GET %s -> text/event-stream at %s:%s",
                     cs$uri, c$id$resp_h, c$id$resp_p),
            $sub=cs$uri,
            $suppress_for=30min
        ]);
        }

    # Tier 2: POST to /mcp or /messages with JSON + SSE accept
    if ( cs$method == "POST" && mcp_path_pattern in cs$uri
         && /application\/json/ in cs$content_type
         && /text\/event-stream/ in cs$accept_hdr )
        {
        log_mcp_detection(c, cs, "MEDIUM",
            fmt("MCP path pattern: POST %s with JSON+SSE accept", cs$uri), "");
        }
    }

## Cleanup connection state
event connection_state_remove(c: connection)
    {
    delete conn_state[c$uid];
    }
