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

# Enumerate subdomains
hadnx subdomains example.com

# Detect WAF
hadnx wafdetect https://example.com

# Check threat intelligence
hadnx threat example.com

# Discover cloud resources (S3, Azure, GCS)
hadnx cloud example.com

# Directory bruteforce
hadnx brute https://example.com -w wordlist.txt

# Check malware reputation
hadnx malware example.com

# Start web server
hadnx serve --host 0.0.0.0 --port 9001
```

### CLI Options

| Command | Description |
|---------|-------------|
| `scan` | Full security scan (headers, cookies, TLS, WAF) |
| `headers` | HTTP security header analysis |
| `cookies` | Cookie security audit |
| `tls` | TLS/SSL configuration check |
| `subdomains` | Subdomain enumeration |
| `cloud` | Cloud resource discovery |
| `wafdetect` | WAF detection |
| `threat` | Threat intelligence lookup |
| `brute` | Directory bruteforce |
| `malware` | Malware/phishing check |
| `serve` | Start web server |

### Scan Options

```bash
# Disable specific checks
hadnx scan https://example.com --no-headers --no-tls

# Verbose mode with detailed findings
hadnx scan https://example.com -V

# Output to JSON file
hadnx scan https://example.com -o report.json
```

## Web Interface Setup

### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Start Celery worker (requires Redis)
celery -A core worker -l info -P eventlet

# Start Django server
python manage.py runserver 9001
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

Visit [http://localhost:5176](http://localhost:5176) to access the application.

## API Endpoints (Core)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scans/` | Initiate a standard security scan |
| GET | `/api/scans/{id}/status/` | Poll for scan progress and status |
| GET | `/api/scans/{id}/chat/` | Retrieve AI chat history for a scan |
| POST | `/api/scans/{id}/chat/` | Send a new message to the AI Consultant |
| POST | `/api/ai-pentest/audit/` | Run autonomous HADNX AI Pentest Pipeline |
| POST | `/api/ai-pentest/exploit/` | Generate & verify exploit for a finding |
| POST | `/api/dos/start/` | Begin DoS simulation on target |
| POST | `/api/repeater/` | Send a manual HTTP request (Repeater) |
| POST | `/api/wireshark/` | Start a packet capture session |

## Project Structure

```
hadnx/
├── hadn/                    # CLI package
│   ├── __init__.py
│   ├── __main__.py
│   └── cli.py               # CLI entry point
├── pyproject.toml           # Package configuration
│
├── backend/                 # Django backend
│   ├── core/                 # Settings, Celery, URLs
│   ├── apps/
│   │   ├── scanner/          # Scan logic, Models, Views
│   │   │   ├── hadnx_ai/     # Agentic Pentesting Pipeline
│   │   │   ├── services/     # Individual tool & analyzer services
│   │   │   ├── tasks.py      # Background task orchestration
│   │   │   └── hadnx_ai/     # Agentic Pentesting Pipeline
│   │   └── reports/          # Compliance mapping & PDF generation
│   └── requirements.txt
│
└── frontend/                 # Next.js frontend
    ├── app/                  # App Router components & pages
    ├── components/           # UI elements (Dashboard, Charts, Chat)
    ├── lib/                  # API client & shared utilities
    └── package.json
```

## Security Philosophy

Hadnx operates on a **Purple Team** philosophy:

1. **Observability First:** We provide clear visibility into security posture through deep analysis.
2. **Verification through Impact:** We enable controlled exploitation to prove that vulnerabilities are real and require immediate attention.
3. **Guardrails & Scope:** Strict domain validation and user authorization ensure that tools are used only on authorized targets.

## License

GNU GENERAL PUBLIC LICENSE Version 3

NOTE: THIS IS JUST A PROJECT
