"""
Cookie Security Analyzer.
Analyzes Set-Cookie headers for security flags and best practices.
"""
from typing import List, Dict, Any
from dataclasses import dataclass, field, asdict
import re


@dataclass
class CookieInfo:
    """Parsed cookie information."""
    name: str
    value: str = ''
    secure: bool = False
    httponly: bool = False
    samesite: str = ''
    path: str = '/'
    domain: str = ''
    expires: str = ''
    max_age: str = ''
    
    def is_session_cookie(self) -> bool:
        """Check if this appears to be a session cookie."""
        session_patterns = ['session', 'sess', 'sid', 'auth', 'token', 'jwt', 'login']
        name_lower = self.name.lower()
        return any(p in name_lower for p in session_patterns)


@dataclass
class FindingData:
    """Data structure for a security finding."""
    issue: str
    severity: str
    category: str = 'cookies'
    impact: str = ''
    recommendation: str = ''
    fix_examples: Dict[str, str] = field(default_factory=dict)
    affected_element: str = ''
    score_impact: int = 0
    # Phase 2 fields
    evidence: str = ''
    poc: str = ''
    confidence: str = 'HIGH'
    description: str = ''
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def parse_set_cookie(header_value: str) -> CookieInfo:
    """
    Parse a Set-Cookie header value into structured data.
    
    Example: "session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/"
    """
    parts = [p.strip() for p in header_value.split(';')]
    
    # First part is name=value
    name_value = parts[0] if parts else ''
    if '=' in name_value:
        name, value = name_value.split('=', 1)
    else:
        name, value = name_value, ''
    
    cookie = CookieInfo(name=name.strip(), value=value.strip())
    
    # Parse attributes
    for part in parts[1:]:
        part_lower = part.lower().strip()
        
        if part_lower == 'secure':
            cookie.secure = True
        elif part_lower == 'httponly':
            cookie.httponly = True
        elif part_lower.startswith('samesite='):
            cookie.samesite = part.split('=', 1)[1].strip()
        elif part_lower.startswith('path='):
            cookie.path = part.split('=', 1)[1].strip()
        elif part_lower.startswith('domain='):
            cookie.domain = part.split('=', 1)[1].strip()
        elif part_lower.startswith('expires='):
            cookie.expires = part.split('=', 1)[1].strip()
        elif part_lower.startswith('max-age='):
            cookie.max_age = part.split('=', 1)[1].strip()
    
    return cookie


def analyze_cookies(set_cookie_headers: List[str], is_https: bool = True) -> List[FindingData]:
    """
    Analyze Set-Cookie headers for security issues.
    
    Args:
        set_cookie_headers: List of Set-Cookie header values
        is_https: Whether the site was accessed over HTTPS
    
    Returns:
        List of FindingData objects representing security findings
    """
    findings: List[FindingData] = []
    
    if not set_cookie_headers:
        return findings
    
    for header_value in set_cookie_headers:
        cookie = parse_set_cookie(header_value)
        
        if not cookie.name:
            continue
        
        is_session = cookie.is_session_cookie()
        severity_boost = 'HIGH' if is_session else 'MEDIUM'
        impact_boost = " This is especially critical as this appears to be a session/auth cookie." if is_session else ""
        
        # Check for missing Secure flag
        if not cookie.secure:
            if is_https:
                findings.append(FindingData(
                    issue=f"Cookie '{cookie.name}' missing Secure flag",
                    severity=severity_boost,
                    category='cookies',
                    impact=f"Without the Secure flag, this cookie can be transmitted over unencrypted HTTP connections, allowing interception.{impact_boost}",
                    recommendation="Add the Secure flag to ensure the cookie is only sent over HTTPS.",
                    fix_examples={
                        'nginx': f'# When setting cookies via proxy:\nproxy_cookie_flags {cookie.name} secure;',
                        'apache': f'Header edit Set-Cookie ^({cookie.name}=.*)$ "$1; Secure"',
                        'django': "# In settings.py:\nSESSION_COOKIE_SECURE = True\nCSRF_COOKIE_SECURE = True",
                        'express': "res.cookie('name', 'value', { secure: true });",
                        'php': "setcookie('name', 'value', ['secure' => true]);",
                    },
                    affected_element=f"Cookie: {cookie.name}",
                    score_impact=8 if is_session else 5
                ))
            else:
                # HTTP site - even worse
                findings.append(FindingData(
                    issue=f"Cookie '{cookie.name}' set over HTTP",
                    severity='CRITICAL' if is_session else 'HIGH',
                    category='cookies',
                    impact=f"Cookies set over HTTP are transmitted in plaintext and can be intercepted by attackers.{impact_boost}",
                    recommendation="Migrate to HTTPS and add the Secure flag to all cookies.",
                    fix_examples={
                        'general': "1. Obtain and install an SSL/TLS certificate\n2. Configure your server for HTTPS\n3. Add Secure flag to all cookies",
                    },
                    affected_element=f"Cookie: {cookie.name}",
                    score_impact=15 if is_session else 10
                ))
        
        # Check for missing HttpOnly flag
        if not cookie.httponly:
            findings.append(FindingData(
                issue=f"Cookie '{cookie.name}' missing HttpOnly flag",
                severity=severity_boost,
                category='cookies',
                impact=f"Without HttpOnly, this cookie can be accessed by JavaScript, making it vulnerable to XSS attacks.{impact_boost}",
                recommendation="Add the HttpOnly flag to prevent client-side script access to the cookie.",
                fix_examples={
                    'nginx': f'proxy_cookie_flags {cookie.name} httponly;',
                    'apache': f'Header edit Set-Cookie ^({cookie.name}=.*)$ "$1; HttpOnly"',
                    'django': "# In settings.py:\nSESSION_COOKIE_HTTPONLY = True\nCSRF_COOKIE_HTTPONLY = True  # Note: May break AJAX if not using Django's CSRF handling",
                    'express': "res.cookie('name', 'value', { httpOnly: true });",
                    'php': "setcookie('name', 'value', ['httponly' => true]);",
                },
                affected_element=f"Cookie: {cookie.name}",
                score_impact=8 if is_session else 5
            ))
        
        # Check for missing SameSite attribute
        if not cookie.samesite:
            findings.append(FindingData(
                issue=f"Cookie '{cookie.name}' missing SameSite attribute",
                severity='MEDIUM',
                category='cookies',
                impact=f"Without SameSite, this cookie may be sent with cross-site requests, enabling CSRF attacks.{impact_boost}",
                recommendation="Add SameSite=Strict or SameSite=Lax to prevent cross-site request forgery.",
                fix_examples={
                    'nginx': f'proxy_cookie_flags {cookie.name} samesite=strict;',
                    'apache': f'Header edit Set-Cookie ^({cookie.name}=.*)$ "$1; SameSite=Strict"',
                    'django': "# In settings.py:\nSESSION_COOKIE_SAMESITE = 'Strict'\nCSRF_COOKIE_SAMESITE = 'Strict'",
                    'express': "res.cookie('name', 'value', { sameSite: 'strict' });",
                    'php': "setcookie('name', 'value', ['samesite' => 'Strict']);",
                },
                affected_element=f"Cookie: {cookie.name}",
                score_impact=5
            ))
        elif cookie.samesite.lower() == 'none':
            # SameSite=None requires Secure
            if not cookie.secure:
                findings.append(FindingData(
                    issue=f"Cookie '{cookie.name}' has SameSite=None without Secure flag",
                    severity='HIGH',
                    category='cookies',
                    impact="SameSite=None cookies without Secure flag are rejected by modern browsers and may be vulnerable to CSRF.",
                    recommendation="Either add the Secure flag or change SameSite to Strict or Lax.",
                    fix_examples={
                        'general': "When using SameSite=None, you MUST also set Secure flag:\nSet-Cookie: name=value; SameSite=None; Secure",
                    },
                    affected_element=f"Cookie: {cookie.name}",
                    score_impact=8
                ))
    
    return findings


def get_cookie_matrix(set_cookie_headers: List[str]) -> List[Dict[str, Any]]:
    """
    Generate a cookie security matrix for UI display.
    
    Returns a list of cookie analysis results with all flags.
    """
    matrix = []
    
    for header_value in set_cookie_headers:
        cookie = parse_set_cookie(header_value)
        if not cookie.name:
            continue
        
        matrix.append({
            'name': cookie.name,
            'secure': cookie.secure,
            'httponly': cookie.httponly,
            'samesite': cookie.samesite or 'Not Set',
            'is_session': cookie.is_session_cookie(),
            'path': cookie.path,
            'domain': cookie.domain,
        })
    
    return matrix


def get_cookie_score(findings: List[FindingData]) -> int:
    """Calculate cookie security score (0-100) based on findings."""
    max_score = 100
    total_impact = sum(f.score_impact for f in findings if f.category == 'cookies')
    
    score = max(0, max_score - total_impact)
    return score
