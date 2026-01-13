"""
Open Redirect Detection.

SAFE, PASSIVE detection only:
- Examines URL parameters for redirect patterns
- Heuristic analysis of common redirect parameters
- Checks for redirect validation

Does NOT:
- Follow any redirects to malicious destinations
- Inject payloads
- Perform parameter manipulation
"""
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, parse_qs
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


# Common redirect parameter names
REDIRECT_PARAMS = [
    'redirect', 'redirect_uri', 'redirect_url',
    'return', 'return_to', 'returnto', 'return_url',
    'next', 'next_url', 'nexturl',
    'url', 'uri', 'path',
    'continue', 'continueto',
    'destination', 'dest', 'go', 'goto',
    'target', 'link', 'out',
    'redir', 'redirect_to', 'rurl',
    'callback', 'callback_url',
]


def test_open_redirect(
    url: str, 
    html_content: Optional[str] = None
) -> AttackSimulationResult:
    """
    Analyze potential open redirect vulnerabilities.
    
    This is a PASSIVE, HEURISTIC check that:
    - Examines URL parameters for redirect patterns
    - Looks for links with redirect parameters in HTML
    
    Does NOT:
    - Test actual redirects
    - Inject malicious URLs
    
    Args:
        url: Target URL to analyze
        html_content: Optional HTML content to examine
        
    Returns:
        AttackSimulationResult with findings
    """
    issues = []
    affected_elements = []
    severity = 'INFO'
    confidence = 'LOW'
    detected = False
    
    # Parse the URL
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    
    # Check URL parameters for redirect patterns
    found_redirect_params = []
    for param in query_params:
        param_lower = param.lower()
        if param_lower in REDIRECT_PARAMS:
            found_redirect_params.append(param)
            values = query_params[param]
            for value in values:
                # Check if the value looks like a URL
                if value.startswith('http') or value.startswith('//') or '://' in value:
                    issues.append(f'Redirect parameter "{param}" contains URL value')
                    severity = 'MEDIUM'
                    confidence = 'MEDIUM'
                    detected = True
                    affected_elements.append(f'{param}={value[:50]}...')
    
    if found_redirect_params and not detected:
        issues.append(f'Potential redirect parameters detected: {", ".join(found_redirect_params)}')
        confidence = 'LOW'
        detected = True
    
    # Check HTML for links with redirect parameters
    if html_content:
        # Look for href attributes containing redirect parameters
        href_pattern = r'href=["\']([^"\']+)["\']'
        hrefs = re.findall(href_pattern, html_content, re.IGNORECASE)
        
        redirect_links = []
        for href in hrefs:
            href_lower = href.lower()
            for param in REDIRECT_PARAMS:
                if f'{param}=' in href_lower or f'{param}%3d' in href_lower:
                    redirect_links.append(href[:100])
                    break
        
        if redirect_links:
            issues.append(f'Found {len(redirect_links)} links with redirect parameters')
            if severity == 'INFO':
                severity = 'LOW'
            detected = True
    
    if detected:
        return AttackSimulationResult(
            issue='Potential Open Redirect Risk',
            confidence=confidence,
            severity=severity,
            detected=True,
            reasoning='; '.join(issues),
            impact='Open redirects can be abused for phishing attacks, bypassing URL filters, '
                   'and redirecting users to malware. They can also be chained with other '
                   'vulnerabilities like OAuth token theft.',
            how_attackers_abuse_this=(
                '1. Attacker finds a URL with redirect parameter: example.com?next=evil.com\n'
                '2. Victim receives a phishing email with the legitimate-looking link\n'
                '3. Victim trusts the domain and clicks the link\n'
                '4. After legitimate site processes the request, victim is redirected to attacker\n'
                '5. Attacker\'s page mimics login or steals credentials'
            ),
            safe_fix={
                'django': '# Validate redirect URLs against a whitelist:\n'
                          'from django.utils.http import url_has_allowed_host_and_scheme\n'
                          'if url_has_allowed_host_and_scheme(redirect_url, allowed_hosts={request.get_host()}):\n'
                          '    return redirect(redirect_url)\n'
                          'else:\n'
                          '    return redirect("/")',
                'express': '// Validate redirect URL\n'
                           'const url = require("url");\n'
                           'const parsed = url.parse(redirectUrl);\n'
                           'const allowed = ["example.com", "sub.example.com"];\n'
                           'if (allowed.includes(parsed.host)) {\n'
                           '    res.redirect(redirectUrl);\n'
                           '} else {\n'
                           '    res.redirect("/");\n'
                           '}',
                'general': '1. Validate all redirect URLs against a whitelist\n'
                           '2. Never use user input directly in redirects\n'
                           '3. Use relative URLs when possible\n'
                           '4. Implement a redirect warning page for external links'
            },
            affected_element=', '.join(affected_elements) if affected_elements else 'Redirect parameters present'
        )
    
    return AttackSimulationResult(
        issue='No Open Redirect Indicators Found',
        confidence='LOW',
        severity='INFO',
        detected=False,
        reasoning='No obvious redirect parameters or patterns detected. Full testing requires '
                  'active probing which is outside our scope.',
        impact='N/A',
        how_attackers_abuse_this='N/A - No issues detected.',
        safe_fix={},
        affected_element='No redirect parameters found'
    )
