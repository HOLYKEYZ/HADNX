"""
NIST 800-53 Control Mapping.
Maps security findings to NIST 800-53 security controls.
"""
from typing import Dict, List, Any


# Selected NIST 800-53 Rev 5 Controls relevant to web security
NIST_800_53_CONTROLS = {
    'SC-8': {
        'family': 'System and Communications Protection',
        'name': 'Transmission Confidentiality and Integrity',
        'description': 'Protect the confidentiality and integrity of transmitted information.',
    },
    'SC-12': {
        'family': 'System and Communications Protection',
        'name': 'Cryptographic Key Establishment and Management',
        'description': 'Establish and manage cryptographic keys.',
    },
    'SC-13': {
        'family': 'System and Communications Protection',
        'name': 'Cryptographic Protection',
        'description': 'Implement cryptographic mechanisms to protect information.',
    },
    'SC-23': {
        'family': 'System and Communications Protection',
        'name': 'Session Authenticity',
        'description': 'Protect the authenticity of communications sessions.',
    },
    'SC-28': {
        'family': 'System and Communications Protection',
        'name': 'Protection of Information at Rest',
        'description': 'Protect the confidentiality and integrity of information at rest.',
    },
    'AC-3': {
        'family': 'Access Control',
        'name': 'Access Enforcement',
        'description': 'Enforce approved authorizations for access to information and system resources.',
    },
    'AC-4': {
        'family': 'Access Control',
        'name': 'Information Flow Enforcement',
        'description': 'Enforce approved authorizations for controlling the flow of information.',
    },
    'IA-5': {
        'family': 'Identification and Authentication',
        'name': 'Authenticator Management',
        'description': 'Manage system authenticators.',
    },
    'IA-8': {
        'family': 'Identification and Authentication',
        'name': 'Identification and Authentication (Non-Organizational Users)',
        'description': 'Identify and authenticate non-organizational users.',
    },
    'CM-6': {
        'family': 'Configuration Management',
        'name': 'Configuration Settings',
        'description': 'Establish and document configuration settings.',
    },
    'CM-7': {
        'family': 'Configuration Management',
        'name': 'Least Functionality',
        'description': 'Configure systems to provide only essential capabilities.',
    },
    'SI-10': {
        'family': 'System and Information Integrity',
        'name': 'Information Input Validation',
        'description': 'Check the validity of information inputs.',
    },
}

# Mapping from finding types to NIST controls
FINDING_TO_NIST_MAP = {
    # TLS/Encryption findings
    'Missing Strict-Transport-Security': ['SC-8', 'SC-13'],
    'Weak TLS version': ['SC-8', 'SC-13'],
    'Weak cipher suite': ['SC-13'],
    'Certificate expired': ['SC-12'],
    
    # Cookie/Session findings
    'Missing Secure flag': ['SC-8', 'SC-23'],
    'Missing HttpOnly flag': ['SC-23', 'AC-3'],
    'Missing SameSite attribute': ['SC-23', 'AC-4'],
    
    # Header findings
    'Missing Content-Security-Policy': ['CM-6', 'SI-10'],
    'Missing X-Frame-Options': ['CM-6', 'AC-4'],
    'Missing X-Content-Type-Options': ['CM-6'],
    
    # Access control findings
    'Potential Clickjacking Risk': ['AC-3', 'AC-4'],
    'CORS Misconfiguration': ['AC-4'],
    'Potential CSRF Risk': ['AC-3', 'IA-8'],
    'Potential Open Redirect Risk': ['SI-10', 'AC-4'],
}


def map_finding_to_nist(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Map a security finding to NIST 800-53 controls.
    """
    issue = finding.get('issue', '')
    mapped_controls = []
    
    for pattern, control_ids in FINDING_TO_NIST_MAP.items():
        if pattern.lower() in issue.lower():
            for control_id in control_ids:
                if control_id in NIST_800_53_CONTROLS:
                    control = NIST_800_53_CONTROLS[control_id].copy()
                    control['id'] = control_id
                    if control not in mapped_controls:
                        mapped_controls.append(control)
            break
    
    if not mapped_controls:
        default_id = 'CM-6'
        control = NIST_800_53_CONTROLS[default_id].copy()
        control['id'] = default_id
        mapped_controls.append(control)
    
    return mapped_controls


def get_nist_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate NIST 800-53 compliance summary.
    """
    control_counts = {ctrl_id: 0 for ctrl_id in NIST_800_53_CONTROLS}
    
    for finding in findings:
        mappings = map_finding_to_nist(finding)
        for mapping in mappings:
            control_counts[mapping['id']] += 1
    
    controls_affected = []
    for ctrl_id, count in control_counts.items():
        if count > 0:
            info = NIST_800_53_CONTROLS[ctrl_id].copy()
            info['id'] = ctrl_id
            info['finding_count'] = count
            controls_affected.append(info)
    
    controls_affected.sort(key=lambda x: x['finding_count'], reverse=True)
    
    return {
        'standard': 'NIST 800-53 Rev 5',
        'total_controls': len(NIST_800_53_CONTROLS),
        'controls_affected': len(controls_affected),
        'compliance_score': round(100 * (1 - len(controls_affected) / len(NIST_800_53_CONTROLS)), 1),
        'controls': controls_affected,
    }
