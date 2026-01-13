"""
Clickjacking Risk Detection.

SAFE, PASSIVE detection only:
- Checks X-Frame-Options header
- Checks CSP frame-ancestors directive
- Attempts to determine if page can be iframed

Does NOT:
- Actually embed the page in an iframe
- Perform any UI manipulation
- Execute any malicious actions
"""
import requests
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class AttackSimulationResult:
    """Result of an attack simulation."""
    issue: str
    confidence: str  # HIGH, MEDIUM, LOW
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
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


def test_clickjacking_risk(url: str, headers: Dict[str, str]) -> AttackSimulationResult:
    """
    Test for clickjacking vulnerability.
    
    This is a PASSIVE check that only examines response headers.
    It does NOT attempt to actually iframe the target.
    
    Args:
        url: Target URL
        headers: Response headers from target
        
    Returns:
        AttackSimulationResult with findings
    """
    # Normalize headers to lowercase
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    x_frame_options = headers_lower.get('x-frame-options', '').upper()
    csp = headers_lower.get('content-security-policy', '')
    
    # Check for frame-ancestors in CSP
    has_frame_ancestors = 'frame-ancestors' in csp.lower()
    frame_ancestors_value = ''
    if has_frame_ancestors:
        try:
            parts = csp.lower().split('frame-ancestors')
            if len(parts) > 1:
                frame_ancestors_value = parts[1].split(';')[0].strip()
        except:
            pass
    
    # Determine risk level
    is_protected = False
    protection_method = None
    weakness = None
    
    if x_frame_options in ('DENY', 'SAMEORIGIN'):
        is_protected = True
        protection_method = f'X-Frame-Options: {x_frame_options}'
    
    if has_frame_ancestors:
        if "'none'" in frame_ancestors_value or "'self'" in frame_ancestors_value:
            is_protected = True
            protection_method = f'CSP frame-ancestors: {frame_ancestors_value}'
        elif '*' in frame_ancestors_value:
            weakness = 'CSP frame-ancestors allows all origins (*)'
    
    # Check for conflicting or weak configurations
    if x_frame_options.startswith('ALLOW-FROM'):
        weakness = 'X-Frame-Options ALLOW-FROM is deprecated and not supported by modern browsers'
    
    if not is_protected:
        return AttackSimulationResult(
            issue='Potential Clickjacking Risk',
            confidence='HIGH' if not x_frame_options and not has_frame_ancestors else 'MEDIUM',
            severity='MEDIUM',
            detected=True,
            reasoning=f'No clickjacking protection detected. '
                     f'X-Frame-Options: {"Not set" if not x_frame_options else x_frame_options}. '
                     f'CSP frame-ancestors: {"Not set" if not has_frame_ancestors else frame_ancestors_value}.',
            impact='Attackers can embed this page in a malicious iframe and trick users into clicking '
                   'hidden buttons or links (UI redress attack). This can lead to unauthorized actions, '
                   'credential theft, or malware installation.',
            how_attackers_abuse_this=(
                '1. Attacker creates a malicious page with an invisible iframe containing the target site\n'
                '2. Victim is tricked into clicking what appears to be a harmless button\n'
                '3. The click is actually registered on the hidden target page\n'
                '4. Unauthorized actions are performed with the victim\'s session'
            ),
            safe_fix={
                'nginx': 'add_header X-Frame-Options "DENY" always;\n'
                         'add_header Content-Security-Policy "frame-ancestors \'none\'" always;',
                'apache': 'Header always set X-Frame-Options "DENY"\n'
                          'Header always set Content-Security-Policy "frame-ancestors \'none\'"',
                'django': 'X_FRAME_OPTIONS = "DENY"\n'
                          '# Or use django-csp with CSP_FRAME_ANCESTORS = ("\'none\'",)',
                'express': 'const helmet = require("helmet");\n'
                           'app.use(helmet.frameguard({ action: "deny" }));'
            },
            affected_element='Missing X-Frame-Options and CSP frame-ancestors'
        )
    
    if weakness:
        return AttackSimulationResult(
            issue='Weak Clickjacking Protection',
            confidence='MEDIUM',
            severity='LOW',
            detected=True,
            reasoning=weakness,
            impact='Current protection may not be effective in all browsers or configurations.',
            how_attackers_abuse_this='Attackers may bypass weak or deprecated protections.',
            safe_fix={
                'nginx': 'add_header X-Frame-Options "DENY" always;\n'
                         'add_header Content-Security-Policy "frame-ancestors \'none\'" always;',
                'apache': 'Header always set X-Frame-Options "DENY"',
                'django': 'X_FRAME_OPTIONS = "DENY"',
                'express': 'app.use(helmet.frameguard({ action: "deny" }));'
            },
            affected_element=weakness
        )
    
    return AttackSimulationResult(
        issue='Clickjacking Protection Present',
        confidence='HIGH',
        severity='INFO',
        detected=False,
        reasoning=f'Site is protected against clickjacking via {protection_method}.',
        impact='No clickjacking risk detected.',
        how_attackers_abuse_this='N/A - Site is protected.',
        safe_fix={},
        affected_element=protection_method
    )
