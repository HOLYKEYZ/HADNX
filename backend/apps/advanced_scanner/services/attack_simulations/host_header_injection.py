"""
Host Header Injection Detection.

SAFE, PASSIVE detection only:
- Examines how server handles Host header variations
- Compares behavior differences

Does NOT:
- Inject malicious Host headers
- Perform cache poisoning
- Exploit any findings
"""
from typing import Dict, Any
from dataclasses import dataclass, asdict


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


def test_host_header_injection(
    url: str,
    headers: Dict[str, str],
    html_content: str = None
) -> AttackSimulationResult:
    """
    Analyze potential host header injection risks.
    
    This is a PASSIVE check that examines:
    - Presence of X-Forwarded-Host in response
    - URL generation patterns in HTML
    
    Does NOT:
    - Send crafted Host headers
    - Perform actual injection
    
    Args:
        url: Target URL
        headers: Response headers from initial request
        html_content: Optional HTML to analyze
        
    Returns:
        AttackSimulationResult with findings
    """
    issues = []
    severity = 'INFO'
    confidence = 'LOW'
    detected = False
    
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    # Check for headers that might indicate forwarding setup
    forwarding_headers = [
        'x-forwarded-host',
        'x-forwarded-for',
        'x-original-url',
        'x-rewrite-url',
    ]
    
    found_forwarding = []
    for header in forwarding_headers:
        if header in headers_lower:
            found_forwarding.append(f'{header}: {headers_lower[header]}')
    
    if found_forwarding:
        issues.append(f'Forwarding headers present: {", ".join(found_forwarding)}')
        # This alone isn't a vulnerability, just indicates architecture
    
    # Analyze HTML for URL generation patterns (if provided)
    if html_content:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        expected_host = parsed.netloc
        
        # Look for absolute URLs that might be dynamically generated
        import re
        absolute_urls = re.findall(r'https?://([^/\'">\s]+)', html_content)
        
        # Check if any URLs use unexpected hosts (could indicate host manipulation)
        # This is a very weak heuristic
        unexpected_hosts = [h for h in absolute_urls if h != expected_host and expected_host not in h]
        
        if len(unexpected_hosts) > 10:
            # Many external hosts is normal, but could indicate something
            pass  # No action, this is too noisy
    
    # Since we can't actively test host header injection without sending
    # modified requests (which would be active scanning), we can only
    # provide general guidance
    
    return AttackSimulationResult(
        issue='Host Header Injection Cannot Be Passively Verified',
        confidence='LOW',
        severity='INFO',
        detected=False,
        reasoning='Host header injection requires active testing with modified headers. '
                  'This passive scan can only identify potential risk indicators.',
        impact='If vulnerable, host header injection can enable cache poisoning, '
               'password reset poisoning, web cache deception, and bypassing access controls.',
        how_attackers_abuse_this=(
            '1. Attacker sends request with crafted Host header\n'
            '2. Application uses Host header to generate URLs\n'
            '3. Generated URLs point to attacker-controlled domain\n'
            '4. Examples: Password reset links, cache poisoning, SSRF'
        ),
        safe_fix={
            'nginx': '# Validate Host header:\n'
                     'server {\n'
                     '    server_name example.com;\n'
                     '    if ($host !~* ^(example\\.com)$) {\n'
                     '        return 444;\n'
                     '    }\n'
                     '}',
            'django': '# Ensure ALLOWED_HOSTS is properly configured:\n'
                      'ALLOWED_HOSTS = ["example.com", "www.example.com"]\n'
                      '# Django validates Host header automatically',
            'express': '// Validate Host header in middleware:\n'
                       'app.use((req, res, next) => {\n'
                       '    const allowedHosts = ["example.com", "www.example.com"];\n'
                       '    if (!allowedHosts.includes(req.hostname)) {\n'
                       '        return res.status(400).send("Bad Request");\n'
                       '    }\n'
                       '    next();\n'
                       '});',
            'general': '1. Never trust the Host header blindly\n'
                       '2. Configure allowed hosts in web server/framework\n'
                       '3. Use absolute URLs from configuration, not headers\n'
                       '4. Validate X-Forwarded-Host if using reverse proxy'
        },
        affected_element='Requires active testing for verification'
    )
