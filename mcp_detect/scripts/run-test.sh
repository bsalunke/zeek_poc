#!/usr/bin/env bash
#
# MCP Server Detection Lab — Run Test
#
# 1. Builds and starts MCP server + tester containers
# 2. Tester generates MCP protocol traffic and captures pcap
# 3. Runs Zeek on the pcap with the MCP detection script
# 4. Displays results
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$LAB_DIR/output"
ZEEK_DIR="$LAB_DIR/zeek"
ZEEK_RESULTS="$OUTPUT_DIR/zeek-results"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   MCP Server Detection Lab — Zeek POC        ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo ""

# Check prerequisites
for cmd in docker zeek; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${RED}[!] Required tool not found: $cmd${NC}"
        exit 1
    fi
done

# Clean previous output
mkdir -p "$OUTPUT_DIR"
rm -f "$OUTPUT_DIR/mcp-traffic.pcap"
rm -rf "$ZEEK_RESULTS"

# Step 1: Build and run containers
echo -e "${YELLOW}[1/4]${NC} Building and starting containers..."
cd "$LAB_DIR"
docker compose build --quiet
docker compose up --abort-on-container-exit 2>&1 | while IFS= read -r line; do
    # Only show tester output, skip build noise
    if [[ "$line" == *"mcp-tester"* ]]; then
        echo "  $line"
    fi
done

echo ""
echo -e "${YELLOW}[2/4]${NC} Stopping containers..."
docker compose down --volumes 2>/dev/null || true

# Step 2: Verify pcap
if [ ! -f "$OUTPUT_DIR/mcp-traffic.pcap" ]; then
    echo -e "${RED}[!] No pcap file found. Something went wrong.${NC}"
    exit 1
fi

PCAP_SIZE=$(ls -lh "$OUTPUT_DIR/mcp-traffic.pcap" | awk '{print $5}')
echo -e "  ${GREEN}[+]${NC} PCAP captured: $PCAP_SIZE"
echo ""

# Step 3: Run Zeek analysis
echo -e "${YELLOW}[3/4]${NC} Running Zeek analysis..."
mkdir -p "$ZEEK_RESULTS"
cd "$ZEEK_RESULTS"
zeek -r "$OUTPUT_DIR/mcp-traffic.pcap" "$ZEEK_DIR/detect-mcp-servers.zeek" 2>&1 || {
    echo -e "${RED}[!] Zeek analysis failed${NC}"
    # Show any error output
    ls -la "$ZEEK_RESULTS/" 2>/dev/null
    exit 1
}

echo -e "  ${GREEN}[+]${NC} Zeek logs generated:"
ls -la "$ZEEK_RESULTS/"*.log 2>/dev/null | awk '{print "      " $NF " (" $5 " bytes)"}'
echo ""

# Step 4: Display results
echo -e "${YELLOW}[4/4]${NC} Results"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo -e "${CYAN}  HTTP Connections Summary (http.log)${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
if [ -f "$ZEEK_RESULTS/http.log" ]; then
    echo ""
    echo "  Method/URI distribution:"
    zeek-cut method uri < "$ZEEK_RESULTS/http.log" 2>/dev/null | sort | uniq -c | sort -rn | while read -r count method uri; do
        printf "    %3d × %-6s %s\n" "$count" "$method" "$uri"
    done
    echo ""
    echo "  Total HTTP transactions: $(zeek-cut ts < "$ZEEK_RESULTS/http.log" 2>/dev/null | wc -l | tr -d ' ')"
fi
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo -e "${CYAN}  MCP Detections (mcp_detect.log)${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
if [ -f "$ZEEK_RESULTS/mcp_detect.log" ]; then
    echo ""
    TOTAL=$(zeek-cut ts < "$ZEEK_RESULTS/mcp_detect.log" 2>/dev/null | wc -l | tr -d ' ')
    echo -e "  ${GREEN}Total MCP detections: $TOTAL${NC}"
    echo ""

    echo "  By detection tier:"
    zeek-cut detection_tier < "$ZEEK_RESULTS/mcp_detect.log" 2>/dev/null | sort | uniq -c | sort -rn | while read -r count tier; do
        color="$NC"
        [[ "$tier" == "HIGH" ]] && color="$RED"
        [[ "$tier" == "MEDIUM" ]] && color="$YELLOW"
        printf "    %3d × ${color}%-8s${NC}\n" "$count" "$tier"
    done
    echo ""

    echo "  By JSON-RPC method:"
    zeek-cut jsonrpc_method < "$ZEEK_RESULTS/mcp_detect.log" 2>/dev/null | sort | uniq -c | sort -rn | while read -r count method; do
        [[ -z "$method" || "$method" == "-" ]] && method="(header-only)"
        printf "    %3d × %s\n" "$count" "$method"
    done
    echo ""

    echo "  By reason:"
    zeek-cut reason < "$ZEEK_RESULTS/mcp_detect.log" 2>/dev/null | sort | uniq -c | sort -rn | while read -r count reason; do
        printf "    %3d × %s\n" "$count" "$reason"
    done
    echo ""

    echo "  Auth status of detected sessions:"
    zeek-cut has_auth < "$ZEEK_RESULTS/mcp_detect.log" 2>/dev/null | sort | uniq -c | while read -r count val; do
        label="No Auth"
        [[ "$val" == "T" ]] && label="Has Auth"
        color="$RED"
        [[ "$val" == "T" ]] && color="$GREEN"
        printf "    %3d × ${color}%s${NC}\n" "$count" "$label"
    done
    echo ""

    echo "  TLS status:"
    zeek-cut has_tls < "$ZEEK_RESULTS/mcp_detect.log" 2>/dev/null | sort | uniq -c | while read -r count val; do
        label="Plaintext HTTP"
        [[ "$val" == "T" ]] && label="TLS"
        color="$RED"
        [[ "$val" == "T" ]] && color="$GREEN"
        printf "    %3d × ${color}%s${NC}\n" "$count" "$label"
    done
else
    echo -e "  ${YELLOW}No mcp_detect.log generated${NC}"
fi
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Notice Log (notice.log)${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
if [ -f "$ZEEK_RESULTS/notice.log" ]; then
    echo ""
    zeek-cut note msg < "$ZEEK_RESULTS/notice.log" 2>/dev/null | while IFS=$'\t' read -r note msg; do
        color="$NC"
        [[ "$msg" == *"[HIGH]"* ]] && color="$RED"
        [[ "$msg" == *"[MEDIUM]"* ]] && color="$YELLOW"
        echo -e "  ${color}$note${NC}"
        echo -e "    $msg"
        echo ""
    done
else
    echo -e "  ${YELLOW}No notices generated${NC}"
fi

echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Done.${NC}"
echo ""
