#!/bin/bash
# Generate self-signed certificates for the test lab
set -e

CERT_DIR="$(cd "$(dirname "$0")/../certs" && pwd)"
mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/server.crt" ] && [ -f "$CERT_DIR/server.key" ]; then
    echo "[*] Certificates already exist in $CERT_DIR, skipping generation."
    echo "    Delete them and re-run to regenerate."
    exit 0
fi

echo "[*] Generating self-signed certificate..."

# Generate RSA private key (2048-bit for compatibility with weak-key detection testing)
openssl genrsa -out "$CERT_DIR/server.key" 2048

# Generate self-signed certificate
openssl req -new -x509 \
    -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -days 365 \
    -subj "/C=US/ST=Test/L=Lab/O=ZeekCipherLab/CN=cipher-test.local" \
    -addext "subjectAltName=DNS:cipher-test.local,DNS:weak-cipher-server,DNS:strong-cipher-server,DNS:localhost,IP:127.0.0.1"

# Also generate a WEAK 1024-bit key cert to test key-length detection
openssl genrsa -out "$CERT_DIR/weak-server.key" 1024

openssl req -new -x509 \
    -key "$CERT_DIR/weak-server.key" \
    -out "$CERT_DIR/weak-server.crt" \
    -days 365 \
    -subj "/C=US/ST=Test/L=Lab/O=ZeekCipherLab/CN=weak-key-server.local"

echo "[+] Certificates generated:"
echo "    $CERT_DIR/server.crt (2048-bit RSA)"
echo "    $CERT_DIR/server.key"
echo "    $CERT_DIR/weak-server.crt (1024-bit RSA — deliberately weak)"
echo "    $CERT_DIR/weak-server.key"

# Show cert details
echo ""
echo "[*] Standard cert details:"
openssl x509 -in "$CERT_DIR/server.crt" -noout -subject -dates -text | grep "Public-Key:"

echo ""
echo "[*] Weak cert details:"
openssl x509 -in "$CERT_DIR/weak-server.crt" -noout -subject -dates -text | grep "Public-Key:"
