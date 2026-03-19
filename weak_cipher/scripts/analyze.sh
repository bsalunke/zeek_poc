#!/bin/bash
#
# Zeek SSL Log Analyzer — Cipher Audit Report
#
# Usage: ./analyze.sh [path-to-ssl.log]
#        ./analyze.sh                     (uses default output location)
#
set -e

LAB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SSL_LOG="${1:-$LAB_DIR/output/zeek-results/ssl.log}"
NOTICE_LOG="$(dirname "$SSL_LOG")/notice.log"
WEAK_LOG="$(dirname "$SSL_LOG")/weak_ciphers.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ ! -f "$SSL_LOG" ]; then
    echo "ERROR: ssl.log not found at $SSL_LOG"
    echo "Usage: $0 [path-to-ssl.log]"
    exit 1
fi

echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}  Zeek SSL/TLS Cipher Audit Report${NC}"
echo -e "${CYAN}================================================${NC}"
echo ""
echo "  Source: $SSL_LOG"
echo "  Generated: $(date)"
echo ""

# ----------------------------
# 1. TLS Version Distribution
# ----------------------------
echo -e "${CYAN}--- 1. TLS Version Distribution ---${NC}"
echo ""
cat "$SSL_LOG" | grep -v "^#" | awk '{print $7}' | sort | uniq -c | sort -rn | while read count version; do
    if echo "$version" | grep -qE "SSLv|TLSv10|TLSv11"; then
        echo -e "  ${RED}$count  $version  ← DEPRECATED${NC}"
    elif echo "$version" | grep -q "TLSv13"; then
        echo -e "  ${GREEN}$count  $version  ← BEST${NC}"
    elif echo "$version" | grep -q "TLSv12"; then
        echo -e "  ${YELLOW}$count  $version  ← OK (check cipher)${NC}"
    else
        echo "  $count  $version"
    fi
done
echo ""

# ----------------------------
# 2. Cipher Suite Distribution
# ----------------------------
echo -e "${CYAN}--- 2. Cipher Suite Distribution ---${NC}"
echo ""
cat "$SSL_LOG" | grep -v "^#" | awk '{print $8}' | sort | uniq -c | sort -rn | while read count cipher; do
    if echo "$cipher" | grep -qiE "RC4|DES|NULL|EXPORT|anon"; then
        echo -e "  ${RED}$count  $cipher  ← WEAK${NC}"
    elif echo "$cipher" | grep -q "^TLS_RSA_"; then
        echo -e "  ${YELLOW}$count  $cipher  ← NO PFS${NC}"
    elif echo "$cipher" | grep -qE "GCM|CHACHA20|POLY1305"; then
        echo -e "  ${GREEN}$count  $cipher  ← STRONG${NC}"
    else
        echo "  $count  $cipher"
    fi
done
echo ""

# ----------------------------
# 3. Weak Cipher Connections
# ----------------------------
echo -e "${CYAN}--- 3. Weak Cipher Connections (Detail) ---${NC}"
echo ""
weak_count=$(cat "$SSL_LOG" | grep -v "^#" | grep -ciE "RC4|DES|NULL|EXPORT|anon" || echo "0")
if [ "$weak_count" -gt 0 ]; then
    echo -e "  ${RED}Found $weak_count connections with weak ciphers:${NC}"
    echo ""
    printf "  %-16s %-16s %-6s %-8s %s\n" "CLIENT" "SERVER" "PORT" "VERSION" "CIPHER"
    printf "  %-16s %-16s %-6s %-8s %s\n" "------" "------" "----" "-------" "------"
    cat "$SSL_LOG" | grep -v "^#" | grep -iE "RC4|DES|NULL|EXPORT|anon" | \
        awk '{printf "  %-16s %-16s %-6s %-8s %s\n", $3, $5, $6, $7, $8}'
else
    echo -e "  ${GREEN}No weak cipher connections found.${NC}"
fi
echo ""

# ----------------------------
# 4. Connections Without PFS
# ----------------------------
echo -e "${CYAN}--- 4. Connections Without Perfect Forward Secrecy ---${NC}"
echo ""
no_pfs=$(cat "$SSL_LOG" | grep -v "^#" | awk '{print $8}' | grep -c "^TLS_RSA_" || echo "0")
if [ "$no_pfs" -gt 0 ]; then
    echo -e "  ${YELLOW}Found $no_pfs connections without PFS:${NC}"
    echo ""
    cat "$SSL_LOG" | grep -v "^#" | awk '$8 ~ /^TLS_RSA_/ {printf "  %-16s %-16s %-8s %s\n", $3, $5, $7, $8}'
else
    echo -e "  ${GREEN}All connections use Perfect Forward Secrecy.${NC}"
fi
echo ""

# ----------------------------
# 5. Deprecated Protocol Connections
# ----------------------------
echo -e "${CYAN}--- 5. Deprecated Protocol Connections ---${NC}"
echo ""
old_proto=$(cat "$SSL_LOG" | grep -v "^#" | awk '{print $7}' | grep -cE "SSLv|TLSv10|TLSv11" || echo "0")
if [ "$old_proto" -gt 0 ]; then
    echo -e "  ${RED}Found $old_proto connections using deprecated protocols:${NC}"
    echo ""
    cat "$SSL_LOG" | grep -v "^#" | grep -E "SSLv|TLSv10|TLSv11" | \
        awk '{printf "  %-16s %-16s %-8s %s\n", $3, $5, $7, $8}'
else
    echo -e "  ${GREEN}All connections use TLS 1.2 or higher.${NC}"
fi
echo ""

# ----------------------------
# 6. Unique Server/Cipher Pairs
# ----------------------------
echo -e "${CYAN}--- 6. Unique Server → Cipher Mappings ---${NC}"
echo ""
printf "  %-20s %-8s %s\n" "SERVER" "VERSION" "CIPHER"
printf "  %-20s %-8s %s\n" "------" "-------" "------"
cat "$SSL_LOG" | grep -v "^#" | awk '{print $5, $7, $8}' | sort -u | \
    while read server version cipher; do
        if echo "$cipher" | grep -qiE "RC4|DES|NULL|EXPORT|anon"; then
            echo -e "  ${RED}$(printf "%-20s %-8s %s" "$server" "$version" "$cipher")${NC}"
        elif echo "$cipher" | grep -q "^TLS_RSA_"; then
            echo -e "  ${YELLOW}$(printf "%-20s %-8s %s" "$server" "$version" "$cipher")${NC}"
        else
            echo -e "  ${GREEN}$(printf "%-20s %-8s %s" "$server" "$version" "$cipher")${NC}"
        fi
    done
echo ""

# ----------------------------
# 7. Zeek Notices Summary
# ----------------------------
echo -e "${CYAN}--- 7. Zeek Notice Alerts ---${NC}"
echo ""
if [ -f "$NOTICE_LOG" ]; then
    notice_count=$(cat "$NOTICE_LOG" | grep -v "^#" | wc -l | tr -d ' ')
    if [ "$notice_count" -gt 0 ]; then
        echo "  Total alerts: $notice_count"
        echo ""
        cat "$NOTICE_LOG" | grep -v "^#" | awk '{print $3}' | sort | uniq -c | sort -rn | \
            while read count note; do
                echo "  $count  $note"
            done
    else
        echo "  No notices generated."
    fi
else
    echo "  notice.log not found."
fi
echo ""

# ----------------------------
# 8. Custom Weak Cipher Log
# ----------------------------
echo -e "${CYAN}--- 8. Custom Weak Cipher Detections ---${NC}"
echo ""
if [ -f "$WEAK_LOG" ]; then
    weak_custom=$(cat "$WEAK_LOG" | grep -v "^#" | wc -l | tr -d ' ')
    if [ "$weak_custom" -gt 0 ]; then
        echo "  Total weak cipher detections: $weak_custom"
        echo ""
        echo "  By risk level:"
        cat "$WEAK_LOG" | grep -v "^#" | awk '{print $11}' | sort | uniq -c | sort -rn | \
            while read count level; do
                case "$level" in
                    CRITICAL) echo -e "    ${RED}$count  $level${NC}" ;;
                    HIGH)     echo -e "    ${RED}$count  $level${NC}" ;;
                    MEDIUM)   echo -e "    ${YELLOW}$count  $level${NC}" ;;
                    *)        echo "    $count  $level" ;;
                esac
            done
        echo ""
        echo "  By reason:"
        cat "$WEAK_LOG" | grep -v "^#" | awk -F'\t' '{print $NF}' | sort | uniq -c | sort -rn
    else
        echo "  No custom weak cipher detections."
    fi
else
    echo "  weak_ciphers.log not found (custom script may not have been loaded)."
fi
echo ""

echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}  End of Report${NC}"
echo -e "${CYAN}================================================${NC}"
