"""
ISO 27001 Annex A Control Mapping.
Maps security findings to ISO 27001:2022 controls.
"""
from typing import Dict, List, Any


# Selected ISO 27001:2022 Annex A Controls relevant to web security
ISO_27001_CONTROLS = {
    'A.5.15': {
        'domain': 'Organizational Controls',
        'name': 'Access Control',
        'description': 'Rules to control physical and logical access to information.',
    },
    'A.5.17': {
        'domain': 'Organizational Controls',
        'name': 'Authentication Information',
        'description': 'Management of authentication information.',
    },
    'A.8.2': {
        'domain': 'Technological Controls',
        'name': 'Privileged Access Rights',
        'description': 'Allocation and use of privileged access rights.',
    },
    'A.8.5': {
        'domain': 'Technological Controls',
        'name': 'Secure Authentication',
        'description': 'Secure authentication technology and procedures.',
    },
    'A.8.9': {
        'domain': 'Technological Controls',
        'name': 'Configuration Management',
        'description': 'Managing security configurations.',
    },
    'A.8.20': {
        'domain': 'Technological Controls',
        'name': 'Networks Security',
        'description': 'Security of networks and network services.',
    },
    'A.8.21': {
        'domain': 'Technological Controls',
        'name': 'Security of Network Services',
        'description': 'Security mechanisms for network services.',
    },
    'A.8.24': {
        'domain': 'Technological Controls',
        'name': 'Use of Cryptography',
        'description': 'Rules for the effective use of cryptography.',
    },
    'A.8.26': {
        'domain': 'Technological Controls',
        'name': 'Application Security Requirements',
        'description': 'Security requirements for applications.',
    },
}

# Mapping from finding types to ISO 27001 controls
FINDING_TO_ISO_MAP = {
    # Cryptographic findings
    'Missing Strict-Transport-Security': ['A.8.24', 'A.8.21'],
    'Weak TLS version': ['A.8.24'],
    'Weak cipher suite': ['A.8.24'],
    
    # Access control findings
    'Missing Secure flag': ['A.5.17', 'A.8.5'],
    'Missing HttpOnly flag': ['A.5.17'],
    'Potential Clickjacking Risk': ['A.8.26', 'A.5.15'],
    'CORS Misconfiguration': ['A.5.15', 'A.8.26'],
    
    # Configuration findings
    'Missing Content-Security-Policy': ['A.8.9', 'A.8.26'],
    'Missing X-Frame-Options': ['A.8.9'],
    'Information Disclosure': ['A.8.9'],
}


def map_finding_to_iso27001(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Map a security finding to ISO 27001 controls.
    """
    issue = finding.get('issue', '')
    mapped_controls = []
    
    for pattern, control_ids in FINDING_TO_ISO_MAP.items():
        if pattern.lower() in issue.lower():
            for control_id in control_ids:
                if control_id in ISO_27001_CONTROLS:
                    control = ISO_27001_CONTROLS[control_id].copy()
                    control['id'] = control_id
                    if control not in mapped_controls:
                        mapped_controls.append(control)
            break
    
    if not mapped_controls:
        default_id = 'A.8.9'
        control = ISO_27001_CONTROLS[default_id].copy()
        control['id'] = default_id
        mapped_controls.append(control)
    
    return mapped_controls


def get_iso27001_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate ISO 27001 compliance summary.
    """
    control_counts = {ctrl_id: 0 for ctrl_id in ISO_27001_CONTROLS}
    
    for finding in findings:
        mappings = map_finding_to_iso27001(finding)
        for mapping in mappings:
            control_counts[mapping['id']] += 1
    
    controls_affected = []
    for ctrl_id, count in control_counts.items():
        if count > 0:
            info = ISO_27001_CONTROLS[ctrl_id].copy()
            info['id'] = ctrl_id
            info['finding_count'] = count
            controls_affected.append(info)
    
    controls_affected.sort(key=lambda x: x['finding_count'], reverse=True)
    
    return {
        'standard': 'ISO 27001:2022',
        'total_controls': len(ISO_27001_CONTROLS),
        'controls_affected': len(controls_affected),
        'compliance_score': round(100 * (1 - len(controls_affected) / len(ISO_27001_CONTROLS)), 1),
        'controls': controls_affected,
    }
