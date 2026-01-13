"""
HTTP Security Header Analyzer.
Detects missing, misconfigured, and deprecated security headers.
"""
from typing import List, Dict, Any, Literal
from dataclasses import dataclass, field, asdict


# Confidence levels for findings
ConfidenceLevel = Literal['HIGH', 'MEDIUM', 'LOW']


@dataclass
class FindingData:
    """Data structure for a security finding."""
    issue: str
    severity: str
    category: str = 'headers'
    impact: str = ''
    recommendation: str = ''
    fix_examples: Dict[str, str] = field(default_factory=dict)
    affected_element: str = ''
    score_impact: int = 0
    # New enhanced fields
    confidence: ConfidenceLevel = 'HIGH'
    evidence: str = ''  # Raw evidence snippet
    description: str = ''  # Detailed description
    cwe_id: str = ''  # CWE reference if applicable
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Security headers and their importance
REQUIRED_HEADERS = {
    'Content-Security-Policy': {
        'severity': 'HIGH',
        'impact': 'Without CSP, the site is vulnerable to XSS attacks, code injection, and data theft.',
        'recommendation': 'Implement a restrictive Content-Security-Policy that limits resource loading to trusted sources.',
        'score_impact': 15,
        'fix_examples': {
            'nginx': "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';\" always;",
            'apache': 'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; font-src \'self\'; connect-src \'self\'; frame-ancestors \'none\';"',
            'django': "# Install django-csp: pip install django-csp\n# In settings.py:\nCSP_DEFAULT_SRC = (\"'self'\",)\nCSP_SCRIPT_SRC = (\"'self'\",)\nCSP_STYLE_SRC = (\"'self'\", \"'unsafe-inline'\")\nCSP_IMG_SRC = (\"'self'\", 'data:')\nCSP_FRAME_ANCESTORS = (\"'none'\",)",
            'express': "const helmet = require('helmet');\napp.use(helmet.contentSecurityPolicy({\n  directives: {\n    defaultSrc: [\"'self'\"],\n    scriptSrc: [\"'self'\"],\n    styleSrc: [\"'self'\", \"'unsafe-inline'\"],\n    imgSrc: [\"'self'\", 'data:'],\n    frameAncestors: [\"'none'\"]\n  }\n}));",
        }
    },
    'Strict-Transport-Security': {
        'severity': 'HIGH',
        'impact': 'Without HSTS, users may be vulnerable to protocol downgrade attacks and cookie hijacking.',
        'recommendation': 'Enable HSTS with a minimum max-age of 1 year (31536000 seconds) and include subdomains.',
        'score_impact': 12,
        'fix_examples': {
            'nginx': 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
            'apache': 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
            'django': "# In settings.py:\nSECURE_HSTS_SECONDS = 31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True\nSECURE_HSTS_PRELOAD = True",
            'express': "const helmet = require('helmet');\napp.use(helmet.hsts({\n  maxAge: 31536000,\n  includeSubDomains: true,\n  preload: true\n}));",
        }
    },
    'X-Frame-Options': {
        'severity': 'MEDIUM',
        'impact': 'Without X-Frame-Options, the site may be vulnerable to clickjacking attacks.',
        'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN to prevent framing by malicious sites.',
        'score_impact': 8,
        'fix_examples': {
            'nginx': 'add_header X-Frame-Options "DENY" always;',
            'apache': 'Header always set X-Frame-Options "DENY"',
            'django': "# In settings.py:\nX_FRAME_OPTIONS = 'DENY'",
            'express': "const helmet = require('helmet');\napp.use(helmet.frameguard({ action: 'deny' }));",
        }
    },
    'X-Content-Type-Options': {
        'severity': 'MEDIUM',
        'impact': 'Without this header, browsers may MIME-sniff responses, potentially executing malicious content.',
        'recommendation': 'Set X-Content-Type-Options to nosniff to prevent MIME type sniffing.',
        'score_impact': 6,
        'fix_examples': {
            'nginx': 'add_header X-Content-Type-Options "nosniff" always;',
            'apache': 'Header always set X-Content-Type-Options "nosniff"',
            'django': "# Django 3.0+ sets this by default\n# Ensure SECURE_CONTENT_TYPE_NOSNIFF = True",
            'express': "const helmet = require('helmet');\napp.use(helmet.noSniff());",
        }
    },
    'Referrer-Policy': {
        'severity': 'LOW',
        'impact': 'Without Referrer-Policy, sensitive URL data may leak to third-party sites.',
        'recommendation': 'Set a restrictive Referrer-Policy like strict-origin-when-cross-origin or no-referrer.',
        'score_impact': 4,
        'fix_examples': {
            'nginx': 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
            'apache': 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
            'django': "# In settings.py:\nSECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'",
            'express': "const helmet = require('helmet');\napp.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
        }
    },
    'Permissions-Policy': {
        'severity': 'LOW',
        'impact': 'Without Permissions-Policy, third-party scripts may access sensitive browser features.',
        'recommendation': 'Define a Permissions-Policy to restrict access to browser features like camera, microphone, and geolocation.',
        'score_impact': 4,
        'fix_examples': {
            'nginx': 'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;',
            'apache': 'Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"',
            'django': "# Add as custom middleware or use django-permissions-policy\n# pip install django-permissions-policy\n# Then add to MIDDLEWARE and configure PERMISSIONS_POLICY",
            'express': "const helmet = require('helmet');\napp.use(helmet.permittedCrossDomainPolicies());\n// For full Permissions-Policy, use additional configuration",
        }
    },
}

# Cross-Origin headers
CROSS_ORIGIN_HEADERS = {
    'Cross-Origin-Opener-Policy': {
        'severity': 'LOW',
        'impact': 'Without COOP, the site may be vulnerable to cross-origin attacks via window references.',
        'recommendation': 'Set Cross-Origin-Opener-Policy to same-origin for stronger isolation.',
        'score_impact': 3,
        'fix_examples': {
            'nginx': 'add_header Cross-Origin-Opener-Policy "same-origin" always;',
            'apache': 'Header always set Cross-Origin-Opener-Policy "same-origin"',
            'django': "# Add custom middleware:\nclass COOPMiddleware:\n    def __init__(self, get_response):\n        self.get_response = get_response\n    def __call__(self, request):\n        response = self.get_response(request)\n        response['Cross-Origin-Opener-Policy'] = 'same-origin'\n        return response",
            'express': "app.use((req, res, next) => {\n  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');\n  next();\n});",
        }
    },
    'Cross-Origin-Embedder-Policy': {
        'severity': 'LOW',
        'impact': 'Without COEP, you cannot use features requiring cross-origin isolation like SharedArrayBuffer.',
        'recommendation': 'Set Cross-Origin-Embedder-Policy to require-corp if you need cross-origin isolation.',
        'score_impact': 2,
        'fix_examples': {
            'nginx': 'add_header Cross-Origin-Embedder-Policy "require-corp" always;',
            'apache': 'Header always set Cross-Origin-Embedder-Policy "require-corp"',
            'django': "# Add to custom middleware alongside COOP\nresponse['Cross-Origin-Embedder-Policy'] = 'require-corp'",
            'express': "app.use((req, res, next) => {\n  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');\n  next();\n});",
        }
    },
    'Cross-Origin-Resource-Policy': {
        'severity': 'LOW',
        'impact': 'Without CORP, your resources may be loaded by cross-origin pages.',
        'recommendation': 'Set Cross-Origin-Resource-Policy to same-origin or same-site based on your needs.',
        'score_impact': 2,
        'fix_examples': {
            'nginx': 'add_header Cross-Origin-Resource-Policy "same-origin" always;',
            'apache': 'Header always set Cross-Origin-Resource-Policy "same-origin"',
            'django': "response['Cross-Origin-Resource-Policy'] = 'same-origin'",
            'express': "app.use((req, res, next) => {\n  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');\n  next();\n});",
        }
    },
}

# Headers that expose information
INFO_DISCLOSURE_HEADERS = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']

# Deprecated headers (should warn if present)
DEPRECATED_HEADERS = {
    'X-XSS-Protection': {
        'severity': 'INFO',
        'impact': 'X-XSS-Protection is deprecated and can introduce vulnerabilities in some browsers.',
        'recommendation': 'Remove X-XSS-Protection header. Use Content-Security-Policy instead for XSS protection.',
        'score_impact': 0,
        'fix_examples': {
            'nginx': '# Remove any add_header X-XSS-Protection directives',
            'apache': '# Remove: Header set X-XSS-Protection',
            'django': '# Django 3.0+ no longer sets this header by default',
            'express': "# If using helmet, it's disabled by default in v4+",
        }
    }
}


def analyze_headers(headers: Dict[str, str]) -> List[FindingData]:
    """
    Analyze HTTP response headers for security issues.
    
    Args:
        headers: Dictionary of HTTP response headers (case-insensitive keys recommended)
    
    Returns:
        List of FindingData objects representing security findings
    """
    findings: List[FindingData] = []
    
    # Normalize headers to case-insensitive lookup
    headers_lower = {k.lower(): v for k, v in headers.items()}
    headers_original = {k.lower(): k for k in headers.keys()}
    
    # Check for missing required security headers
    for header, config in REQUIRED_HEADERS.items():
        header_key = header.lower()
        if header_key not in headers_lower:
            findings.append(FindingData(
                issue=f"Missing {header}",
                severity=config['severity'],
                category='headers',
                impact=config['impact'],
                recommendation=config['recommendation'],
                fix_examples=config['fix_examples'],
                affected_element=header,
                score_impact=config['score_impact']
            ))
        else:
            # Header present - validate value
            value = headers_lower[header_key]
            validation_finding = _validate_header_value(header, value)
            if validation_finding:
                findings.append(validation_finding)
    
    # Check for missing cross-origin headers (lower severity)
    for header, config in CROSS_ORIGIN_HEADERS.items():
        header_key = header.lower()
        if header_key not in headers_lower:
            findings.append(FindingData(
                issue=f"Missing {header}",
                severity=config['severity'],
                category='headers',
                impact=config['impact'],
                recommendation=config['recommendation'],
                fix_examples=config['fix_examples'],
                affected_element=header,
                score_impact=config['score_impact']
            ))
    
    # Check for information disclosure
    for header in INFO_DISCLOSURE_HEADERS:
        header_key = header.lower()
        if header_key in headers_lower:
            original_name = headers_original.get(header_key, header)
            value = headers_lower[header_key]
            findings.append(FindingData(
                issue=f"Information Disclosure: {original_name} header exposed",
                severity='MEDIUM',
                category='info_disclosure',
                impact=f"The {original_name} header reveals server technology ({value}), helping attackers target known vulnerabilities.",
                recommendation=f"Remove or suppress the {original_name} header in production.",
                fix_examples={
                    'nginx': f'# In nginx.conf:\nserver_tokens off;\n# Or use more_clear_headers module:\nmore_clear_headers "{header}";',
                    'apache': f'# In httpd.conf:\nServerTokens Prod\nServerSignature Off\nHeader unset {header}',
                    'django': "# Django doesn't set Server header - this is from your web server\n# Configure nginx/Apache to suppress it",
                    'express': "app.disable('x-powered-by');\n// Or use helmet:\nconst helmet = require('helmet');\napp.use(helmet.hidePoweredBy());",
                },
                affected_element=f"{original_name}: {value}",
                score_impact=5
            ))
    
    # Check for deprecated headers
    for header, config in DEPRECATED_HEADERS.items():
        header_key = header.lower()
        if header_key in headers_lower:
            findings.append(FindingData(
                issue=f"Deprecated Header: {header}",
                severity=config['severity'],
                category='headers',
                impact=config['impact'],
                recommendation=config['recommendation'],
                fix_examples=config['fix_examples'],
                affected_element=f"{header}: {headers_lower[header_key]}",
                score_impact=config['score_impact']
            ))
    
    return findings


def _validate_header_value(header: str, value: str) -> FindingData | None:
    """Validate specific header values for misconfigurations."""
    
    if header == 'Strict-Transport-Security':
        # Check for weak max-age
        if 'max-age=' in value.lower():
            try:
                max_age_str = value.lower().split('max-age=')[1].split(';')[0].strip()
                max_age = int(max_age_str)
                if max_age < 31536000:  # Less than 1 year
                    return FindingData(
                        issue="Weak HSTS max-age value",
                        severity='MEDIUM',
                        category='headers',
                        impact=f"HSTS max-age of {max_age} seconds is too short. Recommended minimum is 1 year (31536000 seconds).",
                        recommendation="Increase HSTS max-age to at least 31536000 seconds (1 year).",
                        fix_examples=REQUIRED_HEADERS['Strict-Transport-Security']['fix_examples'],
                        affected_element=f"Strict-Transport-Security: {value}",
                        score_impact=4
                    )
            except (ValueError, IndexError):
                pass
    
    elif header == 'X-Frame-Options':
        value_upper = value.upper().strip()
        if value_upper not in ('DENY', 'SAMEORIGIN'):
            if value_upper.startswith('ALLOW-FROM'):
                return FindingData(
                    issue="X-Frame-Options ALLOW-FROM is deprecated",
                    severity='MEDIUM',
                    category='headers',
                    impact="ALLOW-FROM is not supported by modern browsers. Use CSP frame-ancestors instead.",
                    recommendation="Replace X-Frame-Options ALLOW-FROM with CSP frame-ancestors directive.",
                    fix_examples={
                        'nginx': "add_header Content-Security-Policy \"frame-ancestors 'self' https://trusted.com\" always;",
                        'apache': 'Header always set Content-Security-Policy "frame-ancestors \'self\' https://trusted.com"',
                        'django': "CSP_FRAME_ANCESTORS = (\"'self'\", 'https://trusted.com')",
                        'express': "// Use CSP frame-ancestors instead of X-Frame-Options ALLOW-FROM",
                    },
                    affected_element=f"X-Frame-Options: {value}",
                    score_impact=4
                )
    
    elif header == 'Content-Security-Policy':
        value_lower = value.lower()
        # Check for unsafe directives
        if "'unsafe-eval'" in value_lower:
            return FindingData(
                issue="CSP contains unsafe-eval",
                severity='MEDIUM',
                category='headers',
                impact="The 'unsafe-eval' directive allows eval() and similar methods, increasing XSS risk.",
                recommendation="Refactor code to avoid eval() and remove 'unsafe-eval' from CSP.",
                fix_examples={
                    'nginx': "# Remove 'unsafe-eval' from your CSP and refactor JavaScript",
                    'apache': "# Remove 'unsafe-eval' from your CSP and refactor JavaScript",
                    'django': "# Remove 'unsafe-eval' from CSP_SCRIPT_SRC",
                    'express': "# Remove 'unsafe-eval' from scriptSrc directive",
                },
                affected_element="Content-Security-Policy contains 'unsafe-eval'",
                score_impact=5
            )
    
    return None


def get_header_score(findings: List[FindingData]) -> int:
    """Calculate header security score (0-100) based on findings."""
    max_score = 100
    total_impact = sum(f.score_impact for f in findings if f.category in ('headers', 'info_disclosure'))
    
    # Cap deductions at 100
    score = max(0, max_score - total_impact)
    return score
