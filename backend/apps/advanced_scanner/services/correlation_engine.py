"""
Risk Correlation Engine.
Combines multiple low-severity findings into high-risk attack chains.
"""
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass


@dataclass
class AttackChain:
    """Represents a potential attack chain."""
    name: str
    severity: str
    probability: str  # HIGH, MEDIUM, LOW
    findings_used: List[str]
    attack_scenario: str
    impact: str
    mitigation_priority: List[str]


# Attack chain patterns - combinations of findings that indicate higher risk
ATTACK_CHAIN_PATTERNS = [
    {
        'name': 'Session Hijacking Chain',
        'required': ['Missing Secure flag', 'Missing HttpOnly flag'],
        'optional': ['Missing Strict-Transport-Security', 'CORS Misconfiguration'],
        'severity': 'CRITICAL',
        'probability': 'HIGH',
        'attack_scenario': '''
1. Attacker intercepts unencrypted network traffic (missing HSTS/Secure flag)
2. Session cookie is captured since it's not marked Secure
3. Or, attacker exploits XSS to steal cookie (missing HttpOnly)
4. CORS misconfig may allow cross-origin access to sensitive data
5. Attacker uses stolen session to impersonate victim''',
        'impact': 'Complete account takeover. Attacker can perform any action as the victim.',
        'mitigation_priority': [
            'Add Secure flag to all session cookies immediately',
            'Add HttpOnly flag to prevent JavaScript access',
            'Enable HSTS with includeSubDomains',
            'Fix CORS configuration to restrict origins',
        ],
    },
    {
        'name': 'Cross-Site Attack Chain',
        'required': ['Missing Content-Security-Policy'],
        'optional': ['Potential Clickjacking Risk', 'Potential CSRF Risk', 'Missing X-Frame-Options'],
        'severity': 'HIGH',
        'probability': 'MEDIUM',
        'attack_scenario': '''
1. Missing CSP allows inline scripts and external resources
2. Attacker injects malicious JavaScript via stored XSS
3. OR: Attacker embeds page in iframe for clickjacking (no X-Frame protection)
4. CSRF vulnerability allows state-changing actions
5. Combined: Victim clicks button thinking it's safe, triggering CSRF + data theft''',
        'impact': 'Data theft, unauthorized actions, credential harvesting.',
        'mitigation_priority': [
            'Implement Content-Security-Policy with strict directives',
            'Add X-Frame-Options DENY header',
            'Implement anti-CSRF tokens',
            'Use SameSite=Strict on cookies',
        ],
    },
    {
        'name': 'Data Interception Chain',
        'required': ['Missing Strict-Transport-Security'],
        'optional': ['Weak TLS version', 'HTTP redirect does not enforce HTTPS', 'Mixed Content'],
        'severity': 'HIGH',
        'probability': 'MEDIUM',
        'attack_scenario': '''
1. Missing HSTS allows protocol downgrade attacks
2. Weak TLS may be exploitable with known attacks
3. HTTP redirect without HSTS enables MITM
4. Mixed content loads resources over HTTP
5. Attacker on same network intercepts sensitive data''',
        'impact': 'All transmitted data (passwords, tokens, PII) can be intercepted.',
        'mitigation_priority': [
            'Enable HSTS with max-age 1 year and includeSubDomains',
            'Upgrade to TLS 1.3 or minimum TLS 1.2',
            'Ensure all redirects are HTTPS',
            'Eliminate all mixed content',
        ],
    },
    {
        'name': 'Information Disclosure Chain',
        'required': ['Information Disclosure'],
        'optional': ['Weak TLS version', 'Server header exposed'],
        'severity': 'MEDIUM',
        'probability': 'MEDIUM',
        'attack_scenario': '''
1. Server/technology headers reveal software versions
2. Attacker researches known vulnerabilities for those versions
3. Weak TLS configuration suggests outdated security practices
4. Combined information helps attacker craft targeted exploits''',
        'impact': 'Enables targeted attacks with higher success probability.',
        'mitigation_priority': [
            'Remove or obscure server version headers',
            'Update all software to latest versions',
            'Upgrade TLS configuration',
        ],
    },
]


def analyze_risk_correlations(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze findings to identify attack chains and correlated risks.
    
    Args:
        findings: List of security findings
        
    Returns:
        Risk correlation analysis with attack chains
    """
    finding_issues = [f.get('issue', '').lower() for f in findings]
    
    detected_chains = []
    
    for pattern in ATTACK_CHAIN_PATTERNS:
        # Check if required findings are present
        required_match = all(
            any(req.lower() in issue for issue in finding_issues)
            for req in pattern['required']
        )
        
        if not required_match:
            continue
        
        # Count optional matches
        optional_matches = [
            opt for opt in pattern['optional']
            if any(opt.lower() in issue for issue in finding_issues)
        ]
        
        # Calculate probability boost from optional findings
        findings_used = pattern['required'] + optional_matches
        probability = pattern['probability']
        
        if len(optional_matches) >= 2:
            probability = 'HIGH'
        elif len(optional_matches) >= 1 and probability != 'HIGH':
            probability = 'MEDIUM'
        
        chain = AttackChain(
            name=pattern['name'],
            severity=pattern['severity'],
            probability=probability,
            findings_used=findings_used,
            attack_scenario=pattern['attack_scenario'].strip(),
            impact=pattern['impact'],
            mitigation_priority=pattern['mitigation_priority'],
        )
        detected_chains.append(chain)
    
    # Calculate overall risk score
    severity_scores = {'CRITICAL': 40, 'HIGH': 30, 'MEDIUM': 15, 'LOW': 5}
    probability_multipliers = {'HIGH': 1.0, 'MEDIUM': 0.6, 'LOW': 0.3}
    
    risk_score = 0
    for chain in detected_chains:
        base_score = severity_scores.get(chain.severity, 10)
        multiplier = probability_multipliers.get(chain.probability, 0.5)
        risk_score += base_score * multiplier
    
    # Cap at 100
    risk_score = min(100, risk_score)
    
    # Determine risk level
    if risk_score >= 70:
        risk_level = 'CRITICAL'
        risk_description = 'Multiple exploitable attack chains detected. Immediate remediation required.'
    elif risk_score >= 40:
        risk_level = 'HIGH'
        risk_description = 'Significant attack surface with potential for chained exploits.'
    elif risk_score >= 20:
        risk_level = 'MEDIUM'
        risk_description = 'Some correlated risks present. Prioritized remediation recommended.'
    else:
        risk_level = 'LOW'
        risk_description = 'Limited correlation between findings. Standard remediation applies.'
    
    return {
        'risk_score': round(risk_score, 1),
        'risk_level': risk_level,
        'risk_description': risk_description,
        'attack_chains': [
            {
                'name': c.name,
                'severity': c.severity,
                'probability': c.probability,
                'findings_used': c.findings_used,
                'attack_scenario': c.attack_scenario,
                'impact': c.impact,
                'mitigation_priority': c.mitigation_priority,
            }
            for c in detected_chains
        ],
        'total_chains_detected': len(detected_chains),
    }


def get_risk_heatmap_data(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate data for risk heatmap visualization.
    """
    categories = ['headers', 'cookies', 'tls', 'https', 'info_disclosure', 'attack_simulation']
    severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    
    heatmap = {cat: {sev: 0 for sev in severities} for cat in categories}
    
    for finding in findings:
        cat = finding.get('category', 'headers')
        sev = finding.get('severity', 'INFO')
        if cat in heatmap and sev in heatmap[cat]:
            heatmap[cat][sev] += 1
    
    return {
        'categories': categories,
        'severities': severities,
        'heatmap': heatmap,
    }
