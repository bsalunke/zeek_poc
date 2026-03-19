# Zeek Weak TLS/SSL Cipher Detection — Research & Reference

> **Date:** 2026-03-18
> **Purpose:** Detect weak, deprecated, and insecure TLS cipher suites in network traffic using Zeek.

---

## Executive Summary

This document covers research and validation of using Zeek to detect weak TLS/SSL cipher suites in container network traffic. A custom detection script (`detect-weak-ciphers.zeek`) was developed with **3 detection signatures** targeting weak ciphers, missing Perfect Forward Secrecy, and deprecated protocol versions. The script was validated in a Docker-based lab environment against two nginx servers (one deliberately weak, one hardened).

**Key findings from lab validation:**
- Zeek successfully detected **7 weak cipher connections** using static RSA key exchange (no PFS)
- The strong server produced **zero alerts** -- all connections used TLS 1.3 with AES-256-GCM
- Modern OpenSSL 3.x (in Alpine nginx) has **removed RC4, DES, 3DES, and SSLv3 at compile time**, shifting detection focus to medium-risk issues (missing PFS, CBC-mode ciphers)
- The custom `weak_ciphers.log` provides structured output with risk levels and human-readable reasons, suitable for SIEM ingestion

---

## Table of Contents

1. [Overview](#1-overview)
2. [How Zeek Inspects TLS Traffic](#2-how-zeek-inspects-tls-traffic)
3. [ssl.log Field Reference](#3-ssllog-field-reference)
4. [Built-in weak-keys.zeek Script](#4-built-in-weak-keyszeek-script)
5. [Weak Cipher Classification](#5-weak-cipher-classification)
6. [Protocol Version Risk Matrix](#6-protocol-version-risk-matrix)
7. [Strong Cipher Baseline (2026)](#7-strong-cipher-baseline-2026)
8. [zeek-cut Command Reference](#8-zeek-cut-command-reference)
9. [Custom Detection Script -- Signatures and Implementation](#9-custom-detection-script----signatures-and-implementation)
10. [Lab Validation -- Findings and Results](#10-lab-validation----findings-and-results)
11. [Continuous Monitoring Pipeline](#11-continuous-monitoring-pipeline)
12. [Key Limitations](#12-key-limitations)
13. [References](#13-references)

---

## 1. Overview

Zeek (formerly Bro) is a network analysis framework that passively monitors network traffic and generates rich, structured logs. For TLS/SSL analysis, Zeek inspects the **plaintext handshake** to extract:

- Negotiated cipher suite
- TLS/SSL protocol version
- Certificate details (subject, issuer, key size)
- Server Name Indication (SNI)
- Session resumption status

This allows detection of weak encryption **without decrypting any traffic**.

### What Zeek Can Detect

| Category | Examples |
|----------|---------|
| Weak ciphers | RC4, DES, 3DES, NULL, EXPORT, anonymous |
| Deprecated protocols | SSLv2, SSLv3, TLS 1.0, TLS 1.1 |
| Weak certificates | RSA keys < 2048 bits, expired certs |
| Missing PFS | Static RSA key exchange (TLS_RSA_*) |
| Weak hash algorithms | MD5, SHA-1 in cipher MAC |

### What Zeek Cannot Detect

- Cipher vulnerabilities that only manifest in the encrypted payload
- Implementation bugs (e.g., Heartbleed) -- Zeek sees the handshake, not the bug
- Post-handshake renegotiation attacks (limited visibility)
- Encrypted TLS 1.3 certificates (cert is in the encrypted portion)

---

## 2. How Zeek Inspects TLS Traffic

Zeek hooks into the TLS handshake at the protocol level:

```
Client                              Server
  |                                   |
  |------- ClientHello -------------->|   Zeek event: ssl_client_hello
  |   (offered ciphers, versions)     |   (sees all cipher suites client supports)
  |                                   |
  |<------ ServerHello ---------------|   Zeek event: ssl_server_hello
  |   (chosen cipher, version)        |   (sees which cipher was NEGOTIATED)
  |                                   |
  |<------ Certificate ---------------|   Zeek event: x509_certificate
  |   (server cert chain)             |   (sees key size, algorithm, validity)
  |                                   |
  |------- ClientKeyExchange -------->|
  |                                   |
  |======= Encrypted Traffic =========|   Zeek cannot see this
  |                                   |   (but doesn't need to for cipher detection)
```

### Key Zeek Events for Cipher Analysis

| Event | When It Fires | Key Parameters |
|-------|--------------|----------------|
| `ssl_client_hello` | Client sends initial hello | `version`, `ciphers` (list of offered suites) |
| `ssl_server_hello` | Server picks cipher | `version`, `cipher` (the chosen suite) |
| `ssl_established` | Handshake completes | `c$ssl` record with full details |
| `ssl_extension` | TLS extension seen | Extension type and data |
| `x509_certificate` | Certificate parsed | Subject, issuer, key type/size |

### The ssl_server_hello Event (Primary Detection Point)

```zeek
event ssl_server_hello(
    c: connection,           # Connection record
    version: count,          # Negotiated TLS version (e.g., TLSv12 = 0x0303)
    record_version: count,   # Record layer version
    possible_ts: time,       # Server timestamp (if present)
    server_random: string,   # Server random bytes
    session_id: string,      # Session ID
    cipher: count,           # Negotiated cipher suite (numeric ID)
    comp_method: count       # Compression method
)
```

The `cipher` parameter is a numeric ID. Zeek maps it via `SSL::cipher_desc[cipher]`.

---

## 3. ssl.log Field Reference

Every TLS/SSL connection produces a row in `ssl.log`:

| Field | Type | Example | Description |
|-------|------|---------|-------------|
| `ts` | time | 1679012345.123456 | Connection timestamp |
| `uid` | string | CYfHzn3pR4WNe0QJi | Unique connection ID |
| `id.orig_h` | addr | 192.168.1.50 | Client IP address |
| `id.orig_p` | port | 49832 | Client port |
| `id.resp_h` | addr | 93.184.216.34 | Server IP address |
| `id.resp_p` | port | 443 | Server port |
| `version` | string | TLSv12 | Negotiated protocol version |
| `cipher` | string | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | Negotiated cipher suite |
| `curve` | string | secp256r1 | Elliptic curve (if ECDHE) |
| `server_name` | string | www.example.com | SNI hostname |
| `resumed` | bool | F | Was session resumed? |
| `established` | bool | T | Did handshake complete? |
| `subject` | string | CN=example.com | Certificate subject |
| `issuer` | string | CN=Let's Encrypt R3 | Certificate issuer |
| `validation_status` | string | ok | Certificate validation result |

### Version String Mapping

| Numeric | Zeek String | Protocol |
|---------|------------|----------|
| 0x0002 | SSLv2 | SSL 2.0 |
| 0x0300 | SSLv3 | SSL 3.0 |
| 0x0301 | TLSv10 | TLS 1.0 |
| 0x0302 | TLSv11 | TLS 1.1 |
| 0x0303 | TLSv12 | TLS 1.2 |
| 0x0304 | TLSv13 | TLS 1.3 |

---

## 4. Built-in weak-keys.zeek Script

Zeek ships with `policy/protocols/ssl/weak-keys.zeek` for out-of-the-box detection.

### How to Enable

Add to `local.zeek`:
```zeek
@load policy/protocols/ssl/weak-keys
```

Or run directly:
```bash
zeek -C -r capture.pcap policy/protocols/ssl/weak-keys.zeek
```

### What It Detects

| Notice Type | Trigger | Default Pattern |
|-------------|---------|-----------------|
| `SSL::Weak_Cipher` | Cipher matches unsafe regex | `/_EXPORT_\|_anon_\|RC4/` |
| `SSL::Weak_Key` | Certificate key < min length | RSA/DSA < 2048 bits |
| `SSL::Old_Version` | Protocol version < minimum | Below TLSv10 |

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `SSL::notify_weak_keys` | `LOCAL_HOSTS` | Which hosts to monitor |
| `SSL::notify_minimal_key_length` | `2048` | Minimum RSA/DSA key size in bits |
| `SSL::tls_minimum_version` | `TLSv10` | Minimum acceptable protocol version |
| `SSL::unsafe_ciphers_regex` | `/(_EXPORT_\|_anon_\|RC4)/` | Pattern matching weak ciphers |

### Limitations of Built-in Script

The default `unsafe_ciphers_regex` only catches EXPORT, anonymous, and RC4. It **misses**:

- DES (single DES, 56-bit)
- 3DES / DES_EDE (Sweet32 vulnerable)
- NULL ciphers (no encryption)
- MD5-based MACs
- Static RSA key exchange (no Perfect Forward Secrecy)
- TLS 1.0 and TLS 1.1 (default minimum is only SSLv3)

---

## 5. Weak Cipher Classification

### By Encryption Algorithm

| Pattern in Cipher Name | Risk | Reason | RFC/CVE |
|------------------------|:----:|--------|---------|
| `NULL` | **Critical** | Zero encryption -- plaintext | RFC 5246 (deprecated) |
| `EXPORT` | **Critical** | Intentionally weakened to 40/56-bit keys | FREAK (CVE-2015-0204) |
| `_anon_` | **Critical** | No server authentication, trivial MITM | RFC 5246 (deprecated) |
| `RC4` | **High** | Multiple statistical biases exploitable | RFC 7465 (prohibited) |
| `DES_CBC` (single) | **High** | 56-bit key, brute-forceable in hours | NIST deprecated 2005 |
| `3DES` / `DES_EDE` | **High** | 64-bit block, Sweet32 birthday attack | CVE-2016-2183 |
| `RC2` | **High** | Weak key schedule, deprecated | RFC 7465 |
| `IDEA` | **Medium** | Deprecated, removed in TLS 1.3 | -- |
| `MD5` (in MAC) | **Medium** | Collision attacks on hash | RFC 6151 |
| `CBC...SHA` (no SHA256+) | **Medium** | BEAST, Lucky13 padding oracle | CVE-2013-0169 |
| `TLS_RSA_*` (no DHE/ECDHE) | **Medium** | No Perfect Forward Secrecy | RFC 7525 (SHOULD NOT) |

### Strong vs Weak Examples

```
STRONG:  TLS_AES_256_GCM_SHA384                         (TLS 1.3, AEAD)
STRONG:  TLS_CHACHA20_POLY1305_SHA256                   (TLS 1.3, AEAD)
STRONG:  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384          (TLS 1.2 + PFS + AEAD)
OK:      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256          (TLS 1.2 + PFS + AEAD)
WEAK:    TLS_RSA_WITH_AES_256_CBC_SHA                   (No PFS, CBC mode)
BAD:     TLS_RSA_WITH_3DES_EDE_CBC_SHA                  (No PFS, 3DES)
AWFUL:   TLS_RSA_WITH_RC4_128_SHA                       (No PFS, RC4 broken)
```

---

## 6. Protocol Version Risk Matrix

| Version | Year | Status (2026) | Known Attacks | Action |
|---------|------|:---:|--------------|--------|
| SSLv2 | 1995 | **Banned** | DROWN, trivially broken | Block immediately |
| SSLv3 | 1996 | **Banned** | POODLE (CVE-2014-3566) | Block immediately |
| TLS 1.0 | 1999 | **Deprecated** | BEAST, CRIME, weak ciphers | Disable |
| TLS 1.1 | 2006 | **Deprecated** | No AEAD ciphers, deprecated by all browsers | Disable |
| TLS 1.2 | 2008 | **OK*** | Safe only with AEAD ciphers (GCM/CCM) | Keep with strong ciphers |
| TLS 1.3 | 2018 | **Best** | Only strong ciphers allowed by spec | Preferred |

*TLS 1.2 is only safe with AEAD cipher suites (AES-GCM, AES-CCM, ChaCha20-Poly1305) + ECDHE/DHE key exchange.

### Industry Deprecation Timeline

| Event | Date |
|-------|------|
| All major browsers disable TLS 1.0/1.1 | March 2020 |
| PCI DSS 4.0 requires TLS 1.2+ | March 2025 |
| NIST SP 800-52 Rev 3 deprecates TLS 1.1 | August 2024 |
| Windows Server 2025 removes RC4/DES/EXPORT | October 2024 |

---

## 7. Strong Cipher Baseline (2026)

### Recommended Cipher Suites (preference order)

**TLS 1.3 (always strong -- only these exist):**
```
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_128_GCM_SHA256
```

**TLS 1.2 (strong subset only):**
```
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

### Quick Assessment Rule

A cipher is strong if ALL of these are true:
1. Key exchange: ECDHE or DHE (provides PFS)
2. Encryption: AES-GCM, AES-CCM, or ChaCha20-Poly1305 (AEAD)
3. Hash: SHA-256 or SHA-384
4. Protocol: TLS 1.2 or 1.3

---

## 8. zeek-cut Command Reference

### Basic Cipher Analysis

```bash
# List all negotiated ciphers with count
cat ssl.log | zeek-cut cipher | sort | uniq -c | sort -rn

# Show cipher + TLS version per connection
cat ssl.log | zeek-cut id.resp_h server_name version cipher

# Find weak ciphers
cat ssl.log | zeek-cut ts id.orig_h id.resp_h server_name version cipher | \
  grep -iE "RC4|DES|NULL|EXPORT|anon|MD5"

# TLS version distribution
cat ssl.log | zeek-cut version | sort | uniq -c | sort -rn

# Find deprecated protocol versions
cat ssl.log | zeek-cut ts id.orig_h id.resp_h server_name version | \
  grep -E "SSLv[23]|TLSv1[01]"

# Show servers using weak ciphers (deduplicated)
cat ssl.log | zeek-cut id.resp_h server_name cipher | \
  grep -iE "RC4|DES|NULL|EXPORT" | sort -u

# Find connections without PFS
cat ssl.log | zeek-cut id.resp_h server_name cipher | grep "TLS_RSA_" | sort -u

# Export to CSV
cat ssl.log | zeek-cut -d ts id.orig_h id.resp_h server_name version cipher > ssl_audit.csv
```

### Advanced Analysis

```bash
# Top 10 servers by connection count
cat ssl.log | zeek-cut id.resp_h | sort | uniq -c | sort -rn | head -10

# Cipher usage by server
cat ssl.log | zeek-cut id.resp_h cipher | sort | uniq -c | sort -rn

# Connections with BOTH weak cipher AND old protocol
cat ssl.log | zeek-cut ts id.orig_h id.resp_h version cipher | \
  grep -E "SSLv|TLSv10" | grep -iE "RC4|DES|NULL"

# Weekly compressed log analysis
for f in /opt/zeek/logs/202*/**/ssl.*.log.gz; do
  zcat "$f"
done | zeek-cut id.resp_h server_name version cipher | \
  grep -iE "RC4|DES|NULL|EXPORT|anon|SSLv|TLSv1[01]" | sort -u
```

---

## 9. Custom Detection Script -- Signatures and Implementation

**Script:** `../zeek/detect-weak-ciphers.zeek` (225 lines)
**Module:** `WeakCipherDetect`
**Hook point:** `ssl_server_hello` event at priority 3

The custom script extends Zeek's built-in `weak-keys.zeek` with broader coverage, structured logging, and risk classification.

### 9.1 Detection Signatures

The script implements **3 detection signatures**, each with its own Notice type and log output:

#### Signature 1: Weak Cipher Detection (`Weak_Cipher_Detected`)

| Attribute | Value |
|-----------|-------|
| **Notice type** | `WeakCipherDetect::Weak_Cipher_Detected` |
| **Trigger event** | `ssl_server_hello` |
| **Match condition** | Negotiated cipher name matches `weak_cipher_pattern` regex |
| **Regex pattern** | `/NULL\|_anon_\|EXPORT\|_DES_\|_RC4_\|_RC2_\|_IDEA_\|DES_CBC\|3DES\|DES.EDE\|_MD5$/` |
| **Risk classification** | CRITICAL: NULL, anonymous, EXPORT; HIGH: RC4, DES, 3DES, RC2, IDEA, MD5 |
| **Suppression** | 1 hour per (server IP, cipher name) pair |
| **Log output** | `weak_ciphers.log` with risk_level and reason fields |

**What it catches:**

| Cipher Pattern | Example Match | Risk |
|---------------|---------------|:----:|
| `NULL` | `TLS_RSA_WITH_NULL_SHA256` | CRITICAL |
| `_anon_` | `TLS_DH_anon_WITH_AES_128_CBC_SHA` | CRITICAL |
| `EXPORT` | `TLS_RSA_EXPORT_WITH_RC4_40_MD5` | CRITICAL |
| `_RC4_` | `TLS_RSA_WITH_RC4_128_SHA` | HIGH |
| `_DES_` / `DES_CBC` | `TLS_RSA_WITH_DES_CBC_SHA` | HIGH |
| `3DES` / `DES.EDE` | `TLS_RSA_WITH_3DES_EDE_CBC_SHA` | HIGH |
| `_RC2_` | `TLS_RSA_WITH_RC2_CBC_MD5` | HIGH |
| `_IDEA_` | `TLS_RSA_WITH_IDEA_CBC_SHA` | HIGH |
| `_MD5$` | `TLS_RSA_WITH_AES_128_CBC_MD5` | HIGH |

#### Signature 2: No Perfect Forward Secrecy (`No_PFS_Detected`)

| Attribute | Value |
|-----------|-------|
| **Notice type** | `WeakCipherDetect::No_PFS_Detected` |
| **Trigger event** | `ssl_server_hello` |
| **Match condition** | Cipher name matches `no_pfs_pattern` AND does NOT match `weak_cipher_pattern` |
| **Regex pattern** | `/^TLS_RSA_/` |
| **Risk classification** | MEDIUM (always) |
| **Suppression** | 1 hour per (server IP, cipher name) pair |
| **Rationale** | Static RSA key exchange means a compromised server key decrypts ALL past traffic |

**What it catches:**

| Cipher | Issue |
|--------|-------|
| `TLS_RSA_WITH_AES_128_CBC_SHA` | No ECDHE/DHE key exchange, CBC mode |
| `TLS_RSA_WITH_AES_256_CBC_SHA256` | No ECDHE/DHE key exchange, CBC mode |
| `TLS_RSA_WITH_AES_128_GCM_SHA256` | No ECDHE/DHE key exchange (AEAD OK, but no PFS) |
| `TLS_RSA_WITH_AES_256_GCM_SHA384` | No ECDHE/DHE key exchange (AEAD OK, but no PFS) |

**Note:** This signature only fires if the cipher did NOT already match the weak cipher regex (to avoid double-counting).

#### Signature 3: Deprecated Protocol Version (`Deprecated_Protocol_Detected`)

| Attribute | Value |
|-----------|-------|
| **Notice type** | `WeakCipherDetect::Deprecated_Protocol_Detected` |
| **Trigger event** | `ssl_server_hello` |
| **Match condition** | Negotiated `version < min_version` (default: 0x0303 = TLS 1.2) |
| **Risk classification** | CRITICAL if version <= SSLv3 (0x0300); HIGH if TLS 1.0/1.1 |
| **Suppression** | 1 hour per (server IP, version) pair |
| **Fires independently** | Can fire alongside Signature 1 or 2 for the same connection |

**What it catches:**

| Version | Hex | Risk |
|---------|-----|:----:|
| SSLv2 | 0x0200 | CRITICAL |
| SSLv3 | 0x0300 | CRITICAL |
| TLS 1.0 | 0x0301 | HIGH |
| TLS 1.1 | 0x0302 | HIGH |

### 9.2 Risk Classification Logic

The script assigns risk levels using a hierarchical function:

```
classify_cipher_risk(cipher_name):
  /NULL|_anon_|EXPORT/          -> CRITICAL
  /RC4|_DES_|DES_CBC|3DES|DES.EDE/ -> HIGH
  /RC2|IDEA|_MD5$/              -> HIGH
  /^TLS_RSA_/                   -> MEDIUM
  default                       -> LOW
```

For deprecated protocols:
```
version <= 0x0300 (SSLv3 or below) -> CRITICAL
version <  0x0303 (TLS 1.0/1.1)   -> HIGH
```

### 9.3 Output: weak_ciphers.log Schema

The script creates a custom log stream written to `weak_ciphers.log`:

| Field | Type | Description |
|-------|------|-------------|
| `ts` | time | Timestamp of the TLS handshake |
| `uid` | string | Zeek connection UID |
| `orig_h` | addr | Client IP |
| `orig_p` | port | Client port |
| `resp_h` | addr | Server IP |
| `resp_p` | port | Server port |
| `server_name` | string | SNI hostname (or `<no-sni>`) |
| `version` | string | TLS version (e.g., TLSv12, SSLv3) |
| `cipher` | string | Negotiated cipher suite name |
| `risk_level` | string | CRITICAL, HIGH, or MEDIUM |
| `reason` | string | Human-readable explanation of the weakness |

### 9.4 Reason Strings

Each detection includes a human-readable reason:

| Cipher Pattern | Reason String |
|---------------|---------------|
| NULL | "NULL cipher -- no encryption" |
| EXPORT | "EXPORT cipher -- deliberately weakened key length" |
| _anon_ | "Anonymous cipher -- no server authentication, MITM trivial" |
| RC4 | "RC4 -- broken stream cipher, banned by RFC 7465" |
| 3DES/DES.EDE | "3DES -- vulnerable to Sweet32 birthday attack (64-bit block)" |
| _DES_/DES_CBC | "Single DES -- 56-bit key, brute-forceable" |
| RC2 | "RC2 -- deprecated, weak key schedule" |
| IDEA | "IDEA -- deprecated, removed from TLS 1.3" |
| _MD5$ | "MD5-based MAC -- collision attacks" |
| ^TLS_RSA_ | "Static RSA -- no Perfect Forward Secrecy" |
| Deprecated proto | "Deprecated protocol SSLv3" / "Deprecated protocol TLSv10" etc. |

### 9.5 Configuration (Redefinable Constants)

All thresholds are `&redef` and can be overridden in `local.zeek`:

```zeek
# Broaden or narrow the weak cipher regex
redef WeakCipherDetect::weak_cipher_pattern = /your-custom-pattern/;

# Change the no-PFS pattern
redef WeakCipherDetect::no_pfs_pattern = /^TLS_RSA_/;

# Change minimum TLS version (default: TLS 1.2 = 0x0303)
redef WeakCipherDetect::min_version = 0x0303;

# Monitor specific hosts (default: ALL_HOSTS)
redef WeakCipherDetect::monitor_hosts = LOCAL_HOSTS;
```

---

## 10. Lab Validation -- Findings and Results

### 10.1 Lab Architecture

```
+----------------------------------------------+
|  Docker Network: cipher-test-net             |
|                                              |
|  +---------------+   +--------------------+  |
|  | nginx-weak    |   | nginx-strong       |  |
|  | 172.18.0.2    |   | 172.18.0.3         |  |
|  | Port 443      |   | Port 443           |  |
|  |               |   |                    |  |
|  | SSLv3,TLS1.0+ |   | TLS 1.2+ only     |  |
|  | ALL ciphers   |   | ECDHE+AES-GCM     |  |
|  | @SECLEVEL=0   |   | (strong only)      |  |
|  +---------------+   +--------------------+  |
|                                              |
|  +----------------------------------------+  |
|  | cipher-tester (nicolaka/netshoot)       |  |
|  | 172.18.0.4                              |  |
|  | - tcpdump capture (port 443)            |  |
|  | - curl with various cipher flags        |  |
|  +----------------------------------------+  |
+----------------------------------------------+
         |
         v  cipher-test.pcap (394 packets, 115KB)
         |
+------------------+
| Zeek Analysis    |
| (Docker: zeek/)  |
| Scripts loaded:  |
|  - weak-keys     |
|  - custom script |
+------------------+
         |
         v
  ssl.log, notice.log, weak_ciphers.log
```

### 10.2 Test Matrix and Results

| # | Test | Target | Cipher Requested | Result | Cipher Negotiated |
|:-:|------|--------|-----------------|--------|-------------------|
| 1 | Default | nginx-weak | (auto) | OK | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 |
| 2 | Force TLS 1.0 | nginx-weak | (auto) | **REJECTED** | N/A (OpenSSL 3.x removed TLS 1.0) |
| 3 | Force TLS 1.1 | nginx-weak | (auto) | **REJECTED** | N/A (OpenSSL 3.x removed TLS 1.1) |
| 4 | Request RC4 | nginx-weak | RC4-SHA | **REJECTED** | N/A (OpenSSL 3.x removed RC4) |
| 5 | Request 3DES | nginx-weak | DES-CBC3-SHA | **REJECTED** | N/A (OpenSSL 3.x removed 3DES) |
| 6 | AES-CBC no PFS | nginx-weak | AES128-SHA | OK | TLS_RSA_WITH_AES_128_CBC_SHA |
| 7 | AES-GCM no PFS | nginx-weak | AES128-GCM-SHA256 | OK | TLS_RSA_WITH_AES_128_GCM_SHA256 |
| 8 | ECDHE+AES-GCM | nginx-weak | ECDHE-RSA-AES128-GCM-SHA256 | OK | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 |
| 9 | Default | nginx-strong | (auto) | OK | TLS_AES_256_GCM_SHA384 (TLS 1.3) |
| 10 | Force TLS 1.3 | nginx-strong | (auto) | OK | TLS_AES_256_GCM_SHA384 (TLS 1.3) |
| 11 | Request RC4 | nginx-strong | RC4-SHA | **REJECTED** | N/A |
| 12 | Request 3DES | nginx-strong | DES-CBC3-SHA | **REJECTED** | N/A |

### 10.3 Cipher Distribution (ssl.log)

Total TLS connections analyzed: **23** (including 2 failed handshakes)

| Count | Version | Cipher | Assessment |
|:-----:|---------|--------|:----------:|
| 7 | TLSv13 | `TLS_AES_256_GCM_SHA384` | STRONG |
| 6 | TLSv12 | `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | STRONG |
| 1 | TLSv12 | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | STRONG |
| 6 | TLSv12 | `TLS_RSA_WITH_AES_128_CBC_SHA` | WEAK (no PFS) |
| 1 | TLSv12 | `TLS_RSA_WITH_AES_128_GCM_SHA256` | WEAK (no PFS) |
| 2 | - | - | Failed handshakes |

### 10.4 Detection Results (notice.log)

Zeek generated **2 unique notices** (suppressed duplicates per 1hr window):

```
WeakCipherDetect::No_PFS_Detected
  [MEDIUM] No PFS: TLS_RSA_WITH_AES_128_CBC_SHA (TLSv12) -- static RSA key exchange
  Server: 172.18.0.2:443 (nginx-weak)

WeakCipherDetect::No_PFS_Detected
  [MEDIUM] No PFS: TLS_RSA_WITH_AES_128_GCM_SHA256 (TLSv12) -- static RSA key exchange
  Server: 172.18.0.2:443 (nginx-weak)
```

### 10.5 Custom Log Results (weak_ciphers.log)

The custom script logged **7 individual detections** before notice suppression:

| Timestamp | Server | Cipher | Risk | Reason |
|-----------|--------|--------|:----:|--------|
| 1773890011.375 | 172.18.0.2 (nginx-weak) | TLS_RSA_WITH_AES_128_CBC_SHA | MEDIUM | Static RSA -- no PFS |
| 1773890011.386 | 172.18.0.2 (nginx-weak) | TLS_RSA_WITH_AES_128_GCM_SHA256 | MEDIUM | Static RSA -- no PFS |
| 1773890011.472 | 172.18.0.2 (nginx-weak) | TLS_RSA_WITH_AES_128_CBC_SHA | MEDIUM | Static RSA -- no PFS |
| 1773890011.529 | 172.18.0.2 (nginx-weak) | TLS_RSA_WITH_AES_128_CBC_SHA | MEDIUM | Static RSA -- no PFS |
| 1773890011.601 | 172.18.0.2 (nginx-weak) | TLS_RSA_WITH_AES_128_CBC_SHA | MEDIUM | Static RSA -- no PFS |
| 1773890011.686 | 172.18.0.2 (nginx-weak) | TLS_RSA_WITH_AES_128_CBC_SHA | MEDIUM | Static RSA -- no PFS |
| 1773890011.714 | 172.18.0.2 (nginx-weak) | TLS_RSA_WITH_AES_128_CBC_SHA | MEDIUM | Static RSA -- no PFS |

**Strong server (nginx-strong): Zero detections.** All 7 connections used TLS 1.3 with `TLS_AES_256_GCM_SHA384` -- no alerts generated.

### 10.6 Key Observations

1. **OpenSSL 3.x has removed the worst ciphers at compile time.** Even with `ssl_ciphers ALL:COMPLEMENTOFALL:+RC4:+DES:+3DES:+NULL:+EXPORT:@SECLEVEL=0` in the nginx config, RC4, DES, 3DES, and NULL ciphers were not available. This means:
   - Legacy servers running OpenSSL 1.x are the primary targets for CRITICAL/HIGH detections
   - Modern servers are more likely to trigger MEDIUM-risk detections (no PFS, CBC mode)

2. **TLS 1.0 and 1.1 are also removed in OpenSSL 3.x.** Despite `ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2` in the weak config, only TLS 1.2 was actually available. The Deprecated_Protocol_Detected signature would fire against older servers.

3. **The no-PFS detection is the most relevant signature for modern infrastructure.** Many production servers still negotiate `TLS_RSA_WITH_AES_*` when clients request it, even if ECDHE suites are preferred.

4. **Zeek's notice suppression works correctly.** While `weak_ciphers.log` recorded all 7 connections, `notice.log` only showed 2 unique alerts (1 per cipher type per server, suppressed for 1hr).

5. **The strong server configuration is validated.** TLS 1.3-only with ECDHE+AES-GCM is the gold standard -- zero detections from any signature.

### 10.7 Reproducing the Lab

```bash
cd zeek-cipher-lab/

# Generate certs
chmod +x scripts/*.sh
./scripts/generate-certs.sh

# Run traffic generation + capture
docker compose up --abort-on-container-exit

# Run Zeek analysis on captured PCAP
docker run --rm \
  -v $(pwd)/output/cipher-test.pcap:/data/capture.pcap:ro \
  -v $(pwd)/zeek/detect-weak-ciphers.zeek:/opt/scripts/detect-weak-ciphers.zeek:ro \
  -v $(pwd)/output/zeek-results:/output \
  zeek/zeek \
  bash -c "cd /output && zeek -C -r /data/capture.pcap \
    policy/protocols/ssl/weak-keys \
    /opt/scripts/detect-weak-ciphers.zeek \
    LogAscii::use_json=F"

# View results
cat output/zeek-results/ssl.log | grep -v "^#"
cat output/zeek-results/notice.log | grep -v "^#"
cat output/zeek-results/weak_ciphers.log | grep -v "^#"

# Detailed analysis
./scripts/analyze.sh
```

---

## 11. Continuous Monitoring Pipeline

```
Live Network Traffic
        |
        v
  Zeek Sensor (weak-keys + custom script)
        |
        +---> ssl.log ---------> SIEM (Splunk/ELK)
        +---> notice.log ------> Alert Pipeline (PagerDuty, Slack)
        +---> weak_ciphers.log > Custom Dashboard
                                     |
                                     v
                              Weekly Cipher Audit Report
```

### JSON Output for SIEM

```bash
zeek -C -r capture.pcap LogAscii::use_json=T
```

### Alert Priority

| Priority | Condition |
|:--------:|-----------|
| P1 | NULL, EXPORT, SSLv2, SSLv3 |
| P2 | RC4, single DES, 3DES |
| P3 | TLS 1.0, TLS 1.1, no PFS |
| P4 | CBC-mode with SHA-1 MAC |

---

## 11. Key Limitations

1. **TLS 1.3 certificates are encrypted** -- Zeek cannot inspect cert details (cipher + version still visible)
2. **Resumed sessions** -- Cipher from original handshake reused, may not appear in new ServerHello
3. **QUIC/HTTP3** -- Limited Zeek support; some encrypted traffic not analyzed
4. **Encrypted Client Hello (ECH)** -- Emerging standard encrypts SNI
5. **JA3/JA4 fingerprinting** -- Not covered here but valuable for TLS fingerprinting beyond cipher detection

---

## 12. References

| Resource | URL |
|----------|-----|
| Zeek ssl.log docs | https://docs.zeek.org/en/master/logs/ssl.html |
| Zeek weak-keys.zeek source | https://github.com/zeek/zeek/blob/master/scripts/policy/protocols/ssl/weak-keys.zeek |
| Zeek SSL events API | https://docs.zeek.org/en/master/scripts/base/bif/plugins/Zeek_SSL.events.bif.zeek.html |
| Zeek base SSL script | https://docs.zeek.org/en/master/scripts/base/protocols/ssl/main.zeek.html |
| RFC 7465 -- Prohibiting RC4 | https://tools.ietf.org/html/rfc7465 |
| RFC 7525 -- TLS Recommendations | https://tools.ietf.org/html/rfc7525 |
| NIST SP 800-52 Rev 3 | https://csrc.nist.gov/publications/detail/sp/800-52/rev-3/final |
| CVE-2016-2183 -- Sweet32 (3DES) | https://nvd.nist.gov/vuln/detail/CVE-2016-2183 |
| CVE-2014-3566 -- POODLE (SSLv3) | https://nvd.nist.gov/vuln/detail/CVE-2014-3566 |
| CVE-2015-0204 -- FREAK (EXPORT) | https://nvd.nist.gov/vuln/detail/CVE-2015-0204 |
| IANA TLS Cipher Suite Registry | https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml |
| Mozilla SSL Config Generator | https://ssl-config.mozilla.org/ |
