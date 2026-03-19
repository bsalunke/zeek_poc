#!/bin/bash
#
# Zeek Weak Cipher Detection Lab — Test Runner
#
# This script:
#   1. Generates self-signed certs (if needed)
#   2. Starts nginx containers (weak + strong ciphers)
#   3. Captures traffic with tcpdump
#   4. Generates TLS connections with various cipher strengths
#   5. Stops capture, runs Zeek analysis
#   6. Displays results
#
set -e

LAB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="$LAB_DIR/output"
PCAP_FILE="$OUTPUT_DIR/cipher-test.pcap"
ZEEK_OUTPUT="$OUTPUT_DIR/zeek-results"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Zeek Weak Cipher Detection Lab${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# ---------------------
# Step 1: Generate certs
# ---------------------
echo -e "${YELLOW}[Step 1/6] Generating certificates...${NC}"
bash "$LAB_DIR/scripts/generate-certs.sh"
echo ""

# ---------------------
# Step 2: Start containers
# ---------------------
echo -e "${YELLOW}[Step 2/6] Starting nginx containers...${NC}"
cd "$LAB_DIR"
docker compose down 2>/dev/null || true
docker compose up -d

# Wait for containers to be healthy
echo "  Waiting for containers to be ready..."
sleep 3

# Verify containers are running
if ! docker ps | grep -q nginx-weak-ciphers; then
    echo -e "${RED}  ERROR: nginx-weak container failed to start${NC}"
    docker compose logs nginx-weak
    exit 1
fi
if ! docker ps | grep -q nginx-strong-ciphers; then
    echo -e "${RED}  ERROR: nginx-strong container failed to start${NC}"
    docker compose logs nginx-strong
    exit 1
fi
echo -e "${GREEN}  Both containers are running.${NC}"
echo ""

# ---------------------
# Step 3: Start packet capture
# ---------------------
echo -e "${YELLOW}[Step 3/6] Starting packet capture...${NC}"
mkdir -p "$OUTPUT_DIR"
rm -f "$PCAP_FILE"

# Capture on loopback for ports 8443 and 8444
sudo tcpdump -i lo0 -w "$PCAP_FILE" "port 8443 or port 8444" &
TCPDUMP_PID=$!
sleep 2

if ! kill -0 $TCPDUMP_PID 2>/dev/null; then
    echo -e "${RED}  ERROR: tcpdump failed to start. Try running with sudo.${NC}"
    exit 1
fi
echo -e "${GREEN}  Capturing traffic (PID: $TCPDUMP_PID)${NC}"
echo ""

# ---------------------
# Step 4: Generate test traffic
# ---------------------
echo -e "${YELLOW}[Step 4/6] Generating TLS test traffic...${NC}"
echo ""

# Common curl options
CURL_OPTS="-s -o /dev/null -w %{ssl_version}/%{ssl_cipher} --connect-timeout 5 -k"

echo -e "  ${CYAN}--- Testing WEAK cipher server (port 8443) ---${NC}"

# Test 1: Let server choose (should pick strongest available)
echo -n "  [1] Default negotiation:        "
result=$(curl $CURL_OPTS https://localhost:8443/ 2>/dev/null) || result="FAILED"
echo -e "${YELLOW}$result${NC}"

# Test 2: Force TLS 1.0
echo -n "  [2] Force TLS 1.0:              "
result=$(curl $CURL_OPTS --tls-max 1.0 --tlsv1.0 https://localhost:8443/ 2>/dev/null) || result="FAILED/REJECTED"
echo -e "${RED}$result${NC}"

# Test 3: Force TLS 1.1
echo -n "  [3] Force TLS 1.1:              "
result=$(curl $CURL_OPTS --tls-max 1.1 --tlsv1.1 https://localhost:8443/ 2>/dev/null) || result="FAILED/REJECTED"
echo -e "${RED}$result${NC}"

# Test 4: Try RC4 cipher
echo -n "  [4] Request RC4:                "
result=$(curl $CURL_OPTS --ciphers RC4-SHA https://localhost:8443/ 2>/dev/null) || result="FAILED/REJECTED"
echo -e "${RED}$result${NC}"

# Test 5: Try 3DES cipher
echo -n "  [5] Request 3DES:               "
result=$(curl $CURL_OPTS --ciphers DES-CBC3-SHA https://localhost:8443/ 2>/dev/null) || result="FAILED/REJECTED"
echo -e "${RED}$result${NC}"

# Test 6: Try AES-CBC without PFS (static RSA)
echo -n "  [6] Request AES-CBC (no PFS):   "
result=$(curl $CURL_OPTS --ciphers AES128-SHA https://localhost:8443/ 2>/dev/null) || result="FAILED/REJECTED"
echo -e "${YELLOW}$result${NC}"

# Test 7: Try AES-GCM without PFS
echo -n "  [7] Request AES-GCM (no PFS):   "
result=$(curl $CURL_OPTS --ciphers AES128-GCM-SHA256 https://localhost:8443/ 2>/dev/null) || result="FAILED/REJECTED"
echo -e "${YELLOW}$result${NC}"

# Test 8: Try ECDHE + AES-GCM (strong)
echo -n "  [8] Request ECDHE+AES-GCM:      "
result=$(curl $CURL_OPTS --ciphers ECDHE-RSA-AES128-GCM-SHA256 https://localhost:8443/ 2>/dev/null) || result="FAILED/REJECTED"
echo -e "${GREEN}$result${NC}"

echo ""
echo -e "  ${CYAN}--- Testing STRONG cipher server (port 8444) ---${NC}"

# Test 9: Default (should get strong cipher)
echo -n "  [9] Default negotiation:        "
result=$(curl $CURL_OPTS https://localhost:8444/ 2>/dev/null) || result="FAILED"
echo -e "${GREEN}$result${NC}"

# Test 10: Force TLS 1.3
echo -n "  [10] Force TLS 1.3:             "
result=$(curl $CURL_OPTS --tlsv1.3 https://localhost:8444/ 2>/dev/null) || result="FAILED/REJECTED"
echo -e "${GREEN}$result${NC}"

# Test 11: Try weak cipher against strong server (should fail)
echo -n "  [11] Request RC4 (expect fail): "
result=$(curl $CURL_OPTS --ciphers RC4-SHA https://localhost:8444/ 2>/dev/null) || result="REJECTED (good!)"
echo -e "${GREEN}$result${NC}"

# Test 12: Try 3DES against strong server (should fail)
echo -n "  [12] Request 3DES (expect fail):"
result=$(curl $CURL_OPTS --ciphers DES-CBC3-SHA https://localhost:8444/ 2>/dev/null) || result="REJECTED (good!)"
echo -e "${GREEN}$result${NC}"

# Make a few more connections for statistical significance
echo ""
echo "  Making additional connections for better statistics..."
for i in $(seq 1 5); do
    curl -s -o /dev/null -k https://localhost:8443/ 2>/dev/null || true
    curl -s -o /dev/null -k https://localhost:8444/ 2>/dev/null || true
done
echo -e "${GREEN}  Done generating traffic.${NC}"
echo ""

# ---------------------
# Step 5: Stop capture and run Zeek
# ---------------------
echo -e "${YELLOW}[Step 5/6] Stopping capture and running Zeek analysis...${NC}"
sleep 2
sudo kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true
sleep 1

echo "  PCAP file: $PCAP_FILE ($(du -h "$PCAP_FILE" | cut -f1))"

# Run Zeek analysis
rm -rf "$ZEEK_OUTPUT"
mkdir -p "$ZEEK_OUTPUT"
cd "$ZEEK_OUTPUT"

# Run Zeek with both built-in weak-keys and custom script
docker run --rm \
    -v "$PCAP_FILE:/data/capture.pcap:ro" \
    -v "$LAB_DIR/zeek/detect-weak-ciphers.zeek:/opt/scripts/detect-weak-ciphers.zeek:ro" \
    -v "$ZEEK_OUTPUT:/output" \
    zeek/zeek \
    bash -c "cd /output && zeek -C -r /data/capture.pcap policy/protocols/ssl/weak-keys /opt/scripts/detect-weak-ciphers.zeek LogAscii::use_json=F"

echo -e "${GREEN}  Zeek analysis complete.${NC}"
echo ""

# ---------------------
# Step 6: Display results
# ---------------------
echo -e "${YELLOW}[Step 6/6] Results${NC}"
echo ""

echo -e "${CYAN}=== CIPHER DISTRIBUTION (ssl.log) ===${NC}"
if [ -f "$ZEEK_OUTPUT/ssl.log" ]; then
    echo ""
    echo "  Version / Cipher counts:"
    cat "$ZEEK_OUTPUT/ssl.log" | grep -v "^#" | awk '{print $7, $8}' | sort | uniq -c | sort -rn | head -20
    echo ""
else
    echo -e "${RED}  No ssl.log generated — check PCAP capture.${NC}"
fi

echo -e "${CYAN}=== WEAK CIPHER ALERTS (notice.log) ===${NC}"
if [ -f "$ZEEK_OUTPUT/notice.log" ]; then
    echo ""
    cat "$ZEEK_OUTPUT/notice.log" | grep -v "^#"
    echo ""
else
    echo "  No notices generated."
fi

echo -e "${CYAN}=== CUSTOM WEAK CIPHER LOG (weak_ciphers.log) ===${NC}"
if [ -f "$ZEEK_OUTPUT/weak_ciphers.log" ]; then
    echo ""
    cat "$ZEEK_OUTPUT/weak_ciphers.log" | grep -v "^#"
    echo ""
else
    echo "  No weak ciphers detected by custom script."
fi

echo -e "${CYAN}=== SUMMARY ===${NC}"
if [ -f "$ZEEK_OUTPUT/ssl.log" ]; then
    total=$(cat "$ZEEK_OUTPUT/ssl.log" | grep -v "^#" | wc -l | tr -d ' ')
    weak=$(cat "$ZEEK_OUTPUT/ssl.log" | grep -v "^#" | grep -ciE "RC4|DES|NULL|EXPORT|anon" || echo "0")
    no_pfs=$(cat "$ZEEK_OUTPUT/ssl.log" | grep -v "^#" | awk '{print $8}' | grep -c "^TLS_RSA_" || echo "0")
    old_ver=$(cat "$ZEEK_OUTPUT/ssl.log" | grep -v "^#" | awk '{print $7}' | grep -cE "SSLv|TLSv10|TLSv11" || echo "0")
    strong=$((total - weak - no_pfs - old_ver))
    if [ "$strong" -lt 0 ]; then strong=0; fi

    echo ""
    echo -e "  Total TLS connections:     $total"
    echo -e "  ${RED}Weak ciphers:              $weak${NC}"
    echo -e "  ${YELLOW}No PFS (static RSA):       $no_pfs${NC}"
    echo -e "  ${RED}Deprecated protocol:       $old_ver${NC}"
    echo -e "  ${GREEN}Strong connections:         ~$strong${NC}"
fi

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "  Output files in: $ZEEK_OUTPUT/"
echo -e "  Run ./scripts/analyze.sh for deeper analysis"
echo -e "${CYAN}============================================${NC}"

# Cleanup containers
echo ""
echo -n "Stop containers? [Y/n] "
read -r answer
if [ "$answer" != "n" ] && [ "$answer" != "N" ]; then
    cd "$LAB_DIR"
    docker compose down
    echo -e "${GREEN}Containers stopped.${NC}"
fi
