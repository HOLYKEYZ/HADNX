"""
CORS Misconfiguration Detection.

SAFE, PASSIVE detection only:
- Examines Access-Control-Allow-Origin header
- Checks for dangerous wildcard configurations
- Detects credential leakage risks

Does NOT:
- Make cross-origin requests
- Exploit any misconfigurations
- Access any protected resources
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


def test_cors_misuse(url: str, headers: Dict[str, str]) -> AttackSimulationResult:
    """
    Test for CORS misconfiguration.
    
    This is a PASSIVE check that only examines response headers.
    It does NOT make cross-origin requests.
    
    Args:
        url: Target URL
        headers: Response headers from target
        
    Returns:
        AttackSimulationResult with findings
    """
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    acao = headers_lower.get('access-control-allow-origin', '')
    acac = headers_lower.get('access-control-allow-credentials', '').lower()
    acam = headers_lower.get('access-control-allow-methods', '')
    acah = headers_lower.get('access-control-allow-headers', '')
    
    issues = []
    severity = 'INFO'
    confidence = 'LOW'
    detected = False
    
    # Check for wildcard with credentials (most dangerous)
    if acao == '*' and acac == 'true':
        return AttackSimulationResult(
            issue='Critical CORS Misconfiguration: Wildcard with Credentials',
            confidence='HIGH',
            severity='CRITICAL',
            detected=True,
            reasoning='The server returns Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. '
                     'This is invalid per CORS spec but some old browsers may accept it.',
            impact='If exploitable, attackers from any origin could steal sensitive data and perform '
                   'actions with user credentials. Session tokens, personal data, and API responses could be exfiltrated.',
            how_attackers_abuse_this=(
                '1. Attacker hosts a malicious page on evil.com\n'
                '2. When victim visits evil.com, JavaScript makes a credentialed request to target\n'
                '3. Browser sends victim\'s cookies with the request\n'
                '4. Response (with sensitive data) is readable by attacker\'s script\n'
                '5. Attacker exfiltrates session tokens, personal info, etc.'
            ),
            safe_fix={
                'nginx': '# Never use * with credentials. Whitelist specific origins:\n'
                         'if ($http_origin ~* "^https://(trusted1\\.com|trusted2\\.com)$") {\n'
                         '    add_header Access-Control-Allow-Origin $http_origin;\n'
                         '    add_header Access-Control-Allow-Credentials true;\n'
                         '}',
                'django': '# In settings.py:\n'
                          'CORS_ALLOWED_ORIGINS = ["https://trusted1.com", "https://trusted2.com"]\n'
                          'CORS_ALLOW_CREDENTIALS = True',
                'express': 'const corsOptions = {\n'
                           '  origin: ["https://trusted1.com", "https://trusted2.com"],\n'
                           '  credentials: true\n'
                           '};\n'
                           'app.use(cors(corsOptions));'
            },
            affected_element='Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true'
        )
    
    # Check for wildcard origin (less severe but still risky)
    if acao == '*':
        issues.append('Wildcard Access-Control-Allow-Origin allows any origin')
        severity = 'MEDIUM'
        confidence = 'MEDIUM'
        detected = True
    
    # Check for credentials without proper origin restriction
    if acac == 'true' and acao:
        if not acao.startswith('https://'):
            issues.append('Credentials allowed for non-HTTPS origin')
            severity = 'HIGH'
            confidence = 'HIGH'
            detected = True
    
    # Check for dynamic origin reflection (potential issue)
    # This would need to be tested with actual requests, which we don't do here
    
    # Check for overly permissive methods
    dangerous_methods = ['DELETE', 'PUT', 'PATCH']
    if acam:
        methods_upper = acam.upper()
        exposed_dangerous = [m for m in dangerous_methods if m in methods_upper]
        if exposed_dangerous:
            issues.append(f'CORS exposes state-changing methods: {", ".join(exposed_dangerous)}')
            if severity == 'INFO':
                severity = 'LOW'
            detected = True
    
    if detected:
        return AttackSimulationResult(
            issue='CORS Misconfiguration Detected',
            confidence=confidence,
            severity=severity,
            detected=True,
            reasoning='; '.join(issues),
            impact='Misconfigured CORS can allow unauthorized cross-origin access to sensitive resources.',
            how_attackers_abuse_this=(
                '1. Attacker identifies the permissive CORS policy\n'
                '2. Creates a malicious page that makes cross-origin requests\n'
                '3. Depending on configuration, can read responses or perform actions\n'
                '4. May be combined with other attacks for greater impact'
            ),
            safe_fix={
                'nginx': '# Whitelist specific trusted origins only\n'
                         'add_header Access-Control-Allow-Origin "https://trusted.com" always;',
                'django': 'CORS_ALLOWED_ORIGINS = ["https://trusted.com"]\n'
                          'CORS_ALLOW_METHODS = ["GET", "POST"]  # Only needed methods',
                'express': 'app.use(cors({ origin: "https://trusted.com" }));'
            },
            affected_element=f'ACAO: {acao}, ACAC: {acac}'
        )
    
    return AttackSimulationResult(
        issue='CORS Configuration Appears Secure',
        confidence='MEDIUM',
        severity='INFO',
        detected=False,
        reasoning='No obvious CORS misconfigurations detected in response headers.',
        impact='N/A',
        how_attackers_abuse_this='N/A - No issues detected.',
        safe_fix={},
        affected_element=f'ACAO: {acao or "Not set"}'
    )
