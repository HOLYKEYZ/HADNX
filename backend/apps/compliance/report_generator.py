"""
Compliance Report Generator.
Generates compliance reports based on scan findings.
"""
from typing import Dict, List, Any

from .mappings import (
    get_owasp_summary,
    get_nist_summary,
    get_iso27001_summary,
    map_finding_to_owasp,
    map_finding_to_nist,
    map_finding_to_iso27001,
)


def generate_compliance_report(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate a comprehensive compliance report for all standards.
    
    Args:
        findings: List of security findings from a scan
        
    Returns:
        Complete compliance report with all mappings
    """
    # Get summaries for each standard
    owasp_summary = get_owasp_summary(findings)
    nist_summary = get_nist_summary(findings)
    iso_summary = get_iso27001_summary(findings)
    
    # Calculate overall compliance score (weighted average)
    overall_score = (
        owasp_summary['compliance_score'] * 0.4 +
        nist_summary['compliance_score'] * 0.35 +
        iso_summary['compliance_score'] * 0.25
    )
    
    # Determine overall compliance status
    if overall_score >= 90:
        status = 'EXCELLENT'
        status_description = 'Your security posture meets or exceeds industry standards.'
    elif overall_score >= 70:
        status = 'GOOD'
        status_description = 'Minor improvements recommended to meet all compliance requirements.'
    elif overall_score >= 50:
        status = 'NEEDS_IMPROVEMENT'
        status_description = 'Significant gaps exist in compliance coverage. Remediation recommended.'
    else:
        status = 'CRITICAL'
        status_description = 'Critical compliance gaps detected. Immediate action required.'
    
    # Enrich findings with compliance mappings
    enriched_findings = []
    for finding in findings:
        enriched = finding.copy()
        enriched['compliance'] = {
            'owasp': map_finding_to_owasp(finding),
            'nist': map_finding_to_nist(finding),
            'iso27001': map_finding_to_iso27001(finding),
        }
        enriched_findings.append(enriched)
    
    return {
        'overall_score': round(overall_score, 1),
        'status': status,
        'status_description': status_description,
        'standards': {
            'owasp': owasp_summary,
            'nist': nist_summary,
            'iso27001': iso_summary,
        },
        'findings': enriched_findings,
        'remediation_priority': _generate_remediation_priority(findings),
    }


def _generate_remediation_priority(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Generate prioritized remediation recommendations.
    """
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    
    # Group findings by issue for deduplication
    unique_issues = {}
    for finding in findings:
        issue = finding.get('issue', '')
        severity = finding.get('severity', 'INFO')
        if issue not in unique_issues or severity_order.get(severity, 4) < severity_order.get(unique_issues[issue]['severity'], 4):
            unique_issues[issue] = finding
    
    # Sort by severity
    prioritized = sorted(
        unique_issues.values(),
        key=lambda x: severity_order.get(x.get('severity', 'INFO'), 4)
    )
    
    return [
        {
            'priority': idx + 1,
            'issue': f.get('issue', ''),
            'severity': f.get('severity', 'INFO'),
            'recommendation': f.get('recommendation', ''),
            'impact': f.get('impact', ''),
        }
        for idx, f in enumerate(prioritized[:10])  # Top 10 priorities
    ]
