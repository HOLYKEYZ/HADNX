# Hadnx - Web Security Posture Analysis Platform

A production-grade, hybrid offensive/defensive web security platform that analyzes live websites for vulnerabilities, security headers, and compliance, while providing interactive pentesting tools.

## Features

- **🛡️ Defensive Analysis**
  - **HTTP Security Headers** - Detect missing CSP, HSTS, X-Frame-Options
  - **Cookie Security Audit** - Check Secure, HttpOnly, SameSite flags
  - **TLS/SSL Verification** - Validate protocol versions, cipher strength
  - **HTTPS Enforcement** - Detect mixed content and redirect issues

- **⚔️ Offensive Tools (Interactive Suite)**
  - **Nuclei Scanner** - Fast template-based vulnerability scanning
  - **OWASP ZAP** - Full web application scanner (Spider & Active Scan)
  - **SQLMap** - Automated SQL injection detection and exploitation
  - **Nmap** - Network port scanning and service detection
  - **Repeater** - Manual request crafting and replay
  - **Wireshark** - Packet capture and analysis via Tshark

- **🧠 AI Security Consultant**
  - **Gemini Integration** - Explain findings, generate PoCs, and suggest fixes
  - **Chat Interface** - Context-aware security consultations
  - **Persistence** - Chat history saved per scan

- **📊 Reporting & Compliance**
  - **Weighted Scoring** - 0-100 score with A+ to F grades
  - **Compliance Reports** - OWASP Top 10, NIST, ISO 27001
  - **PDF Export** - Professional audit reports

## Tech Stack

### Backend
- Python 3.12 / Django 5 / Django REST Framework
- Celery + Redis for async scanning
- PostgreSQL (Production) / SQLite (Dev)
- **Tools:** `python-nmap`, `python-owasp-zap-v2.4`, `sqlmap`, `nuclei`, `tshark`

### Frontend
- Next.js 14 (App Router) / TypeScript
- Tailwind CSS / shadcn/ui
- Recharts for visualizations
- `react-markdown` for AI responses

## Quick Start

### Prerequisites
- Python 3.12+
- Node.js 18+
- Redis server
- **External Tools:** Nmap, Wireshark (Tshark), OWASP ZAP (Installed locally)

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

# Start Redis (in separate terminal)
# redis-server

# Start Celery worker (in separate terminal)
celery -A core worker -l info -P eventlet

# Start Django server on port 9001
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

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scans/` | Start new scan |
| GET | `/api/scans/` | List all scans |
| GET | `/api/scans/{id}/` | Get scan details |
| POST | `/api/scans/{id}/chat/` | Chat with AI Consultant |
| POST | `/api/scans/zap/` | Control OWASP ZAP |
| POST | `/api/scans/nmap/` | Run Network Scan |

## Project Structure

```
hadnx/
├── backend/                 # Django backend
│   ├── core/                 # Settings, Celery, URLs
│   ├── apps/
│   │   ├── scanner/          # Scan logic & Tool Services
│   │   │   ├── services/     # Analyzers, AI, ZAP, Nmap, etc.
│   │   │   ├── models.py
│   │   │   ├── views.py
│   │   │   └── tasks.py
│   │   └── reports/          # Compliance mapping
│   └── requirements.txt
│
└── frontend/                 # Next.js frontend
    ├── app/                  # App Router pages
    ├── components/           # UI components
    ├── lib/                  # API client, utils
    └── package.json
```

## Security Philosophy

Hadnx has evolved into a balanced **Purple Team** platform:

- ✅ **Defensive:** Observes, analyzes, scores posture, and provides remediation.
- ✅ **Offensive:** Verification-focused exploitation to prove impact (with user consent).
- ✅ **Authorized Use Only:** Strict scope validation to prevent misuse.

## License

GNU GENERAL PUBLIC LICENSE Version 3