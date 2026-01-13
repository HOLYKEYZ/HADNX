"""
Compliance mapping module exports.
"""
from .owasp import map_finding_to_owasp, get_owasp_summary, OWASP_TOP_10_2021
from .nist import map_finding_to_nist, get_nist_summary, NIST_800_53_CONTROLS
from .iso27001 import map_finding_to_iso27001, get_iso27001_summary, ISO_27001_CONTROLS

__all__ = [
    'map_finding_to_owasp', 'get_owasp_summary', 'OWASP_TOP_10_2021',
    'map_finding_to_nist', 'get_nist_summary', 'NIST_800_53_CONTROLS',
    'map_finding_to_iso27001', 'get_iso27001_summary', 'ISO_27001_CONTROLS',
]
