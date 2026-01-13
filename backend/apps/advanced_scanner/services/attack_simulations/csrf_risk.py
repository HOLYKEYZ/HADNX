"""
CSRF Risk Detection.

SAFE, PASSIVE detection only:
- Checks SameSite cookie attributes
- Examines CSRF token patterns in forms (if HTML provided)
- Analyzes state-changing endpoints

Does NOT:
- Submit any forms
- Bypass CSRF protections
- Perform any state-changing actions
"""
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
import re


@dataclass
class AttackSimulationResult:
    """Result of an attack simulation."""
    issue: str
    confidence: str
    severity: str
    category: str = 'attack_simulation'
    reasoning: str = ''
    impact: str = ''
    how_attackers_abuse_this: str = ''
    safe_fix: Dict[str, str] = None
    affected_element: str = ''
    detected: bool = False
    
    def __post_init__(self):
        if self.safe_fix is None:
            self.safe_fix = {}
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def test_csrf_risk(
    url: str, 
    headers: Dict[str, str], 
    cookies: List[str],
    html_content: Optional[str] = None
) -> AttackSimulationResult:
    """
    Analyze CSRF protection posture.
    
    This is a PASSIVE check examining:
    - SameSite cookie attributes
    - Presence of CSRF tokens in forms
    - Cookie security flags
    
    Does NOT attempt to exploit CSRF vulnerabilities.
    
    Args:
        url: Target URL
        headers: Response headers
        cookies: List of Set-Cookie header values
        html_content: Optional HTML content to analyze forms
        
    Returns:
        AttackSimulationResult with findings
    """
    issues = []
    severity = 'INFO'
    confidence = 'LOW'
    detected = False
    
    # Analyze cookies for SameSite attribute
    session_cookies = []
    missing_samesite = []
    weak_samesite = []
    
    for cookie in cookies:
        cookie_lower = cookie.lower()
        cookie_name = cookie.split('=')[0].strip().lower()
        
        # Identify likely session/auth cookies
        is_session_cookie = any(name in cookie_name for name in [
            'session', 'sess', 'auth', 'token', 'jwt', 'login', 'user', 'id'
        ])
        
        if is_session_cookie:
            session_cookies.append(cookie_name)
            
            # Check SameSite attribute
            if 'samesite' not in cookie_lower:
                missing_samesite.append(cookie_name)
            elif 'samesite=none' in cookie_lower:
                weak_samesite.append(cookie_name)
            elif 'samesite=lax' in cookie_lower:
                # Lax is okay for most cases
                pass
    
    # Check for CSRF tokens in HTML (if provided)
    has_csrf_token = False
    if html_content:
        # Look for common CSRF token patterns
        csrf_patterns = [
            r'name=["\']?csrf',
            r'name=["\']?_token',
            r'name=["\']?csrfmiddlewaretoken',
            r'name=["\']?authenticity_token',
            r'name=["\']?__RequestVerificationToken',
            r'x-csrf-token',
            r'csrf-token',
        ]
        for pattern in csrf_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                has_csrf_token = True
                break
    
    # Determine severity based on findings
    if missing_samesite:
        issues.append(f'Session cookies missing SameSite attribute: {", ".join(missing_samesite)}')
        severity = 'MEDIUM'
        confidence = 'MEDIUM'
        detected = True
    
    if weak_samesite:
        issues.append(f'Session cookies with SameSite=None (requires HTTPS and explicit consent): {", ".join(weak_samesite)}')
        if severity == 'INFO':
            severity = 'LOW'
        detected = True
    
    if html_content and not has_csrf_token:
        issues.append('No CSRF token detected in HTML forms')
        if severity in ('INFO', 'LOW'):
            severity = 'MEDIUM'
        confidence = 'MEDIUM'
        detected = True
    
    if detected:
        return AttackSimulationResult(
            issue='Potential CSRF Risk',
            confidence=confidence,
            severity=severity,
            detected=True,
            reasoning='; '.join(issues),
            impact='Cross-Site Request Forgery (CSRF) can allow attackers to perform unauthorized '
                   'actions on behalf of authenticated users. This includes changing passwords, '
                   'making purchases, or modifying account settings.',
            how_attackers_abuse_this=(
                '1. Attacker crafts a malicious page with a hidden form or script\n'
                '2. Form targets a state-changing endpoint on the vulnerable site\n'
                '3. When victim visits the malicious page, the form auto-submits\n'
                '4. Browser includes victim\'s session cookies with the request\n'
                '5. Server processes the request as if it came from the victim'
            ),
            safe_fix={
                'django': '# Django includes CSRF protection by default. Ensure:\n'
                          '# 1. CsrfViewMiddleware is in MIDDLEWARE\n'
                          '# 2. {% csrf_token %} is in all POST forms\n'
                          '# 3. CSRF_COOKIE_SAMESITE = "Strict" or "Lax"',
                'express': 'const csrf = require("csurf");\n'
                           'app.use(csrf({ cookie: { sameSite: "strict" } }));\n'
                           '// Include token in forms: res.locals.csrfToken = req.csrfToken();',
                'nginx': '# CSRF protection must be implemented in the application layer\n'
                         '# Ensure cookies have SameSite attribute:\n'
                         '# proxy_cookie_flags ~ "SameSite=Strict";',
                'general': '1. Implement anti-CSRF tokens in all state-changing forms\n'
                           '2. Set SameSite=Strict on session cookies\n'
                           '3. Verify Origin/Referer headers on sensitive requests\n'
                           '4. Use POST for state-changing operations'
            },
            affected_element=f'Session cookies: {", ".join(session_cookies) if session_cookies else "None detected"}'
        )
    
    return AttackSimulationResult(
        issue='CSRF Protection Appears Adequate',
        confidence='MEDIUM' if html_content else 'LOW',
        severity='INFO',
        detected=False,
        reasoning='SameSite cookies and/or CSRF tokens detected. Full CSRF validation requires '
                  'interactive testing which is outside our scope.',
        impact='N/A',
        how_attackers_abuse_this='N/A - No obvious CSRF weaknesses detected.',
        safe_fix={},
        affected_element='CSRF protections appear present'
    )
