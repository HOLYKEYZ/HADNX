# Hadnx - Web Security Posture Analysis Platform

A production-grade, hybrid offensive/defensive web security platform that analyzes live websites for vulnerabilities, security headers, and compliance, while providing interactive pentesting tools and an autonomous AI security agent.

## Features

### 🛡️ Defensive Analysis & Compliance
- **HTTP Security Headers** - Detect missing CSP, HSTS, X-Frame-Options, etc.
- **Cookie Security Audit** - Check Secure, HttpOnly, SameSite flags, and cookie longevity.
- **TLS/SSL Verification** - Validate protocol versions, cipher strength, and certificate validity.
- **WAF Detection** - identify Cloudflare, AWS WAF, Akamai, and other protection layers.
- **Malware & Phishing Check** - Check domain reputation and content for malicious snippets.
- **Weighted Scoring** - 0-100 score with A+ to F grades based on findings.
- **Compliance Reports** - Mapping to OWASP Top 10, NIST, and ISO 27001 standards.

### 🔍 Reconnaissance & OSINT
- **Subdomain Enumeration** - Passive (CRT.sh) and Active (DNS Bruteforce) discovery.
- **Cloud Resource Discovery** - Scan for open S3 buckets, Azure Blobs, and Google Storage.
- **Threat Intelligence** - Integration with AlienVault OTX and PulseDive for reputation checks.
- **Directory Bruteforce** - Customizable wordlist-based path discovery.

### ⚔️ Offensive Tools (Interactive Suite)
- **Shannon AI Pentester** - Autonomous AI agent (HADNX Agent) for recon, vulnerability analysis, and exploit generation.
- **DoS/DDoS Simulator** - Stress test targets using HTTP Flood and Slowloris (Authorized use only).
- **Nuclei Scanner** - Powerful template-based vulnerability scanning.
- **OWASP ZAP** - Full-featured web scanner for Spidering and Active Scanning.
- **SQLMap** - Automated tool for SQL injection detection and database takeover.
- **Nmap** - Industry-standard port scanning and service fingerprinting.
- **Repeater** - Manually craft, modify, and replay HTTP requests.
- **Wireshark (Tshark)** - Real-time packet capture and interface analysis.

### 🧠 AI Security Consultant (Gemini)
- **Context-Aware Analysis** - Get expert explanations for any finding.
- **Interactive Chat** - Persisted chat history per scan for continuous consultation.
- **Remediation & PoCs** - Generate fix recommendations and Proof-of-Concept verification steps.

## Tech Stack

### Backend
- **Core:** Python 3.12 / Django 5 / Django REST Framework
- **Concurrency:** Celery + Redis for asynchronous scanning tasks
- **Database:** PostgreSQL (Production) / SQLite (Development)
- **Key Libraries:** `google-generativeai`, `python-nmap`, `python-owasp-zap-v2.4`, `sqlmap`, `nuclei`, `tshark`, `reportlab`

### Frontend
- **Framework:** Next.js 14 (App Router) / TypeScript
- **Styling:** Tailwind CSS / shadcn/ui
- **Visualization:** Recharts & Framer Motion
- **Features:** Real-time progress tracking, Markdown rendering, Inter font family

## Quick Start

### Prerequisites
- **Python 3.12+**
- **Node.js 18+**
- **Redis server**
- **External Dependencies:** Ensure `nmap`, `tshark` (Wireshark), `nuclei`, and `sqlmap` are in your PATH or installed in the default locations.

## CLI Usage

Hadnx provides a powerful CLI for running security scans directly from the terminal.

### Install CLI

```bash
# From project root
pip install -e .

# Or install dependencies manually
pip install click requests cryptography beautifulsoup4 dnspython
```

### Quick CLI Commands

```bash
# Show help
hadnx --help

# ═══════════════════════════════════════════════════════════════
# DEFENSIVE SCANNING
# ═══════════════════════════════════════════════════════════════

# Run full security scan
hadnx scan https://example.com

# Scan with verbose output and save report
hadnx scan https://example.com -V -o report.json

# Analyze HTTP headers only
hadnx headers https://example.com

# Analyze cookie security
hadnx cookies https://example.com

# Analyze TLS/SSL configuration
hadnx tls https://example.com

# ═══════════════════════════════════════════════════════════════
# RECONNAISSANCE & OSINT
# ═══════════════════════════════════════════════════════════════

# Enumerate subdomains
hadnx subdomains example.com

# Discover cloud resources (S3, Azure, GCS)
hadnx cloud example.com

# Check threat intelligence
hadnx threat example.com

# Directory bruteforce
hadnx brute https://example.com -w wordlist.txt

# Detect WAF
hadnx wafdetect https://example.com

# Check malware reputation
hadnx malware example.com

# ═══════════════════════════════════════════════════════════════
# AI PENTESTER (Autonomous)
# ═══════════════════════════════════════════════════════════════

# Run full AI pentest audit
hadnx ai audit https://example.com

# Quick AI scan (no exploitation)
hadnx ai audit https://example.com --quick

# Save AI audit report
hadnx ai audit https://example.com -o ai-report.json

# Check AI agent health/configuration
hadnx ai health
