"""
OWASP Top 10 Mapping.
Maps security findings to OWASP Top 10 2021 categories.
"""
from typing import Dict, List, Any


# OWASP Top 10 2021 Categories
OWASP_TOP_10_2021 = {
    'A01:2021': {
        'name': 'Broken Access Control',
        'description': 'Access control enforces policy such that users cannot act outside of their intended permissions.',
        'url': 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
    },
    'A02:2021': {
        'name': 'Cryptographic Failures',
        'description': 'Previously known as Sensitive Data Exposure, this category focuses on failures related to cryptography.',
        'url': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    },
    'A03:2021': {
        'name': 'Injection',
        'description': 'Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.',
        'url': 'https://owasp.org/Top10/A03_2021-Injection/',
    },
    'A04:2021': {
        'name': 'Insecure Design',
        'description': 'A new category focusing on risks related to design flaws.',
        'url': 'https://owasp.org/Top10/A04_2021-Insecure_Design/',
    },
    'A05:2021': {
        'name': 'Security Misconfiguration',
        'description': 'Security misconfiguration is the most commonly seen issue.',
        'url': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    },
    'A06:2021': {
        'name': 'Vulnerable and Outdated Components',
        'description': 'Components with known vulnerabilities may undermine application defenses.',
        'url': 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
    },
    'A07:2021': {
        'name': 'Identification and Authentication Failures',
        'description': 'Confirmation of user identity, authentication, and session management is critical.',
        'url': 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
    },
    'A08:2021': {
        'name': 'Software and Data Integrity Failures',
        'description': 'Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations.',
        'url': 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
    },
    'A09:2021': {
        'name': 'Security Logging and Monitoring Failures',
        'description': 'This category helps detect, escalate, and respond to active breaches.',
        'url': 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/',
    },
    'A10:2021': {
        'name': 'Server-Side Request Forgery',
        'description': 'SSRF flaws occur when a web app fetches a remote resource without validating the user-supplied URL.',
        'url': 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/',
    },
}

# Mapping from finding categories/issues to OWASP categories
FINDING_TO_OWASP_MAP = {
    # Header-related findings
    'Missing Content-Security-Policy': ['A05:2021', 'A03:2021'],
    'CSP contains unsafe-eval': ['A05:2021', 'A03:2021'],
    'Missing Strict-Transport-Security': ['A02:2021', 'A05:2021'],
    'Weak HSTS max-age value': ['A02:2021', 'A05:2021'],
    'Missing X-Frame-Options': ['A05:2021'],
    'Missing X-Content-Type-Options': ['A05:2021'],
    'Missing Referrer-Policy': ['A05:2021'],
    'Missing Permissions-Policy': ['A05:2021'],
    
    # Cookie-related findings
    'Missing Secure flag': ['A02:2021', 'A07:2021'],
    'Missing HttpOnly flag': ['A07:2021', 'A03:2021'],
    'Missing SameSite attribute': ['A07:2021', 'A01:2021'],
    'Cookie over HTTP': ['A02:2021'],
    
    # TLS-related findings
    'Weak TLS version': ['A02:2021'],
    'Weak cipher suite': ['A02:2021'],
    'Certificate expired': ['A02:2021'],
    'Certificate not trusted': ['A02:2021'],
    
    # Attack simulation findings
    'Potential Clickjacking Risk': ['A01:2021', 'A05:2021'],
    'CORS Misconfiguration': ['A01:2021', 'A05:2021'],
    'Critical CORS Misconfiguration': ['A01:2021'],
    'Potential CSRF Risk': ['A01:2021'],
    'Potential Open Redirect Risk': ['A01:2021', 'A03:2021'],
    'Host Header Injection': ['A05:2021', 'A10:2021'],
    
    # Information disclosure
    'Information Disclosure': ['A05:2021'],
}


def map_finding_to_owasp(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Map a security finding to OWASP Top 10 categories.
    
    Args:
        finding: Finding dictionary with 'issue' key
        
    Returns:
        List of OWASP categories with full details
    """
    issue = finding.get('issue', '')
    mapped_categories = []
    
    # Check for exact matches first
    for pattern, owasp_ids in FINDING_TO_OWASP_MAP.items():
        if pattern.lower() in issue.lower():
            for owasp_id in owasp_ids:
                if owasp_id in OWASP_TOP_10_2021:
                    category = OWASP_TOP_10_2021[owasp_id].copy()
                    category['id'] = owasp_id
                    if category not in mapped_categories:
                        mapped_categories.append(category)
            break
    
    # Default to Security Misconfiguration if no specific mapping
    if not mapped_categories:
        default_id = 'A05:2021'
        category = OWASP_TOP_10_2021[default_id].copy()
        category['id'] = default_id
        mapped_categories.append(category)
    
    return mapped_categories


def get_owasp_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate OWASP Top 10 compliance summary.
    
    Args:
        findings: List of security findings
        
    Returns:
        Summary with counts per OWASP category
    """
    category_counts = {owasp_id: 0 for owasp_id in OWASP_TOP_10_2021}
    category_findings = {owasp_id: [] for owasp_id in OWASP_TOP_10_2021}
    
    for finding in findings:
        owasp_mappings = map_finding_to_owasp(finding)
        for mapping in owasp_mappings:
            owasp_id = mapping['id']
            category_counts[owasp_id] += 1
            category_findings[owasp_id].append(finding.get('issue', ''))
    
    # Build summary
    categories_affected = []
    for owasp_id, count in category_counts.items():
        if count > 0:
            info = OWASP_TOP_10_2021[owasp_id].copy()
            info['id'] = owasp_id
            info['finding_count'] = count
            info['findings'] = category_findings[owasp_id][:5]  # Top 5 findings
            categories_affected.append(info)
    
    # Sort by count (most findings first)
    categories_affected.sort(key=lambda x: x['finding_count'], reverse=True)
    
    return {
        'standard': 'OWASP Top 10 2021',
        'total_categories': len(OWASP_TOP_10_2021),
        'categories_affected': len(categories_affected),
        'compliance_score': round(100 * (1 - len(categories_affected) / len(OWASP_TOP_10_2021)), 1),
        'categories': categories_affected,
    }
