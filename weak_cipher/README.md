# Zeek Weak Cipher Detection Lab

A containerized lab environment to validate TLS cipher detection using Zeek. Runs nginx servers with deliberately weak and strong cipher configurations, captures traffic, and analyzes it with Zeek to identify insecure cipher suites.

## Architecture

```
┌──────────────────────────────────────────────┐
│  Docker Network: cipher-test-net             │
│                                              │
│  ┌───────────────┐   ┌────────────────────┐  │
│  │ nginx-weak    │   │ nginx-strong       │  │
│  │ Port 8443     │   │ Port 8444          │  │
│  │               │   │                    │  │
│  │ RC4, DES,     │   │ TLS 1.2+ only     │  │
│  │ 3DES, NULL,   │   │ AES-GCM + ECDHE   │  │
│  │ TLS 1.0/1.1   │   │ (strong ciphers)  │  │
│  └───────────────┘   └────────────────────┘  │
│                                              │
└──────────────────────────────────────────────┘
         │ captured via tcpdump
         ▼
┌──────────────────┐
│ Zeek Analysis    │
│ (Docker: zeek/)  │
│                  │
│ ssl.log          │
│ notice.log       │
│ weak_ciphers.log │
└──────────────────┘
```

## Prerequisites

- Docker and Docker Compose
- tcpdump (pre-installed on macOS/Linux)
- Zeek Docker image: `docker pull zeek/zeek`

## Quick Start

```bash
# 1. Make scripts executable
chmod +x scripts/*.sh

# 2. Run the full test
sudo ./scripts/run-test.sh
```

The test script will:
1. Generate self-signed TLS certificates
2. Start two nginx containers (weak + strong ciphers)
3. Capture traffic with tcpdump
4. Make TLS connections using various cipher suites
5. Run Zeek analysis on the captured PCAP
6. Display a color-coded results summary

## Manual Steps

### Generate Certificates
```bash
./scripts/generate-certs.sh
```

### Start Containers
```bash
docker compose up -d
```

### Capture and Analyze
```bash
# Capture traffic
sudo tcpdump -i lo0 -w output/capture.pcap "port 8443 or port 8444" &

# Make test connections
curl -k https://localhost:8443/          # Weak server
curl -k https://localhost:8444/          # Strong server
curl -k --ciphers RC4-SHA https://localhost:8443/   # Force RC4

# Stop capture, run Zeek
kill %1
docker run --rm -v $(pwd)/output:/data zeek/zeek \
  bash -c "cd /data && zeek -C -r capture.pcap policy/protocols/ssl/weak-keys"
```

### Analyze Results
```bash
./scripts/analyze.sh output/zeek-results/ssl.log
```

## Files

```
zeek-cipher-lab/
├── README.md
├── docker-compose.yml              # Two nginx containers
├── docs/
│   └── ZEEK-WEAK-CIPHER-DETECTION.md  # Full research document
├── nginx/
│   ├── nginx-weak.conf             # Weak ciphers enabled
│   └── nginx-strong.conf           # Strong ciphers only
├── zeek/
│   └── detect-weak-ciphers.zeek    # Custom detection script
├── scripts/
│   ├── generate-certs.sh           # Self-signed cert generator
│   ├── run-test.sh                 # Full automated test
│   └── analyze.sh                  # SSL log analyzer
├── certs/                          # Generated certificates
└── output/                         # PCAP and Zeek results
```

## Expected Results

After running the test, you should see:

**Weak server (port 8443):** Connections flagged for RC4, 3DES, DES, TLS 1.0/1.1, and missing PFS

**Strong server (port 8444):** Only TLS 1.2/1.3 with ECDHE+AES-GCM — no alerts

## Custom Zeek Script

The `zeek/detect-weak-ciphers.zeek` script extends Zeek's built-in detection with:

- Broader weak cipher regex (DES, 3DES, NULL, MD5, RC2, IDEA, anonymous)
- Perfect Forward Secrecy checking (flags static RSA)
- Protocol version enforcement (minimum TLS 1.2)
- Dedicated `weak_ciphers.log` with risk levels and reasons

## Documentation

See `docs/ZEEK-WEAK-CIPHER-DETECTION.md` for the complete research document covering:

- How Zeek inspects TLS handshakes
- ssl.log field reference
- Weak cipher classification with CVE references
- zeek-cut command reference
- Continuous monitoring pipeline design
