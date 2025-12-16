# Hadnx - Web Security Posture Analysis Platform

A production-grade, defensive web security auditing platform that analyzes live websites for security headers, cookies, TLS/SSL configuration, and HTTPS enforcement.

## Features

- **HTTP Security Headers Analysis** - Detect missing CSP, HSTS, X-Frame-Options, and more
- **Cookie Security Audit** - Check Secure, HttpOnly, SameSite flags
- **TLS/SSL Verification** - Validate protocol versions, cipher strength, certificates
- **HTTPS Enforcement** - Detect mixed content and redirect issues
- **Weighted Scoring** - 0-100 score with A+ to F grades
- **Framework-Specific Fixes** - nginx, Apache, Django, Express remediation guides

## Tech Stack

### Backend
- Python 3.12 / Django 5 / Django REST Framework
- Celery + Redis for async scanning
- BeautifulSoup, requests, httpx, cryptography

### Frontend
- Next.js 14 (App Router) / TypeScript
- Tailwind CSS / shadcn/ui
- Recharts for visualizations

## Quick Start

### Prerequisites
- Python 3.12+
- Node.js 18+
- Redis server

### Backend Setup

```bash
cd aegisweb

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
celery -A core worker -l info

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

Visit http://localhost:3000 to access the application.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scans/` | Start new scan |
| GET | `/api/scans/` | List all scans |
| GET | `/api/scans/{id}/` | Get scan details |
| GET | `/api/scans/{id}/status/` | Poll scan status |

## Project Structure

```
hadnx/
├── aegisweb/                 # Django backend
│   ├── core/                 # Settings, Celery, URLs
│   ├── apps/
│   │   ├── scanner/          # Scan logic
│   │   │   ├── services/     # Analyzers
│   │   │   ├── models.py
│   │   │   ├── views.py
│   │   │   └── tasks.py
│   │   └── reports/
│   └── requirements.txt
│
└── frontend/                 # Next.js frontend
    ├── app/                  # App Router pages
    ├── components/           # UI components
    ├── lib/                  # API client, utils
    └── package.json
```

## Security Philosophy

Hadnx is a **defensive** security tool:
- ✅ Observes and analyzes
- ✅ Scores posture
- ✅ Provides remediation
- ❌ No exploitation
- ❌ No brute force
- ❌ No payloads

## License

MIT
