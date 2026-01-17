"""
WAF Fingerprinting Service.
Detects Web Application Firewalls using headers and behavioral analysis.
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
import requests

@dataclass
class FindingData:
    """Data structure for a security finding."""
    issue: str
    severity: str
    category: str = 'waf'
    impact: str = ''
    recommendation: str = ''
    fix_examples: Dict[str, str] = field(default_factory=dict)
    affected_element: str = ''
    score_impact: int = 0
    # Phase 2 fields
    confidence: str = 'HIGH'
    evidence: str = ''
    poc: str = ''
    description: str = ''
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

WAF_SIGNATURES = {
    'Cloudflare': {
        'headers': {'server': 'cloudflare', 'cf-ray': None},
        'cookies': ['__cfduid', 'cf_clearance']
    },
    'AWS WAF': {
        'headers': {'x-amz-cf-id': None, 'via': 'cloudfront'},
        'cookies': []
    },
    'Akamai': {
        'headers': {'server': 'akamai', 'x-akamai-transformed': None},
        'cookies': []
    },
    'Imperva Incapsula': {
        'headers': {'x-iinfo': None, 'x-cdn': 'incapsula'},
        'cookies': ['incap_ses', 'visid_incap']
    },
    'F5 BIG-IP': {
        'headers': {'server': 'big-ip', 'x-cnection': 'close'},
        'cookies': ['bigipsummary', 'f5_cspm']
    },
    'Barracuda': {
        'headers': {'x-barra-cookie': None},
        'cookies': ['barra_counter_session']
    }
}

def detect_waf(headers: Dict[str, str], cookies: List[str]) -> List[FindingData]:
    """
    Analyze response to fingerprint WAFs.
    """
    findings = []
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    
    # Cookies list from fetch_url contains "Name=Value; ...". extracting names simple way
    cookie_names = []
    for c in cookies:
        if '=' in c:
            cookie_names.append(c.split('=')[0].strip())
    
    detected_wafs = set()

    for waf_name, sig in WAF_SIGNATURES.items():
        # Check headers
        for h_name, h_val_match in sig['headers'].items():
            if h_name in headers_lower:
                if h_val_match is None: # Just existence checks
                    detected_wafs.add(waf_name)
                elif h_val_match in headers_lower[h_name]: # substring match
                    detected_wafs.add(waf_name)
        
        # Check cookies
        for c_pattern in sig['cookies']:
            if any(c_pattern in c_name for c_name in cookie_names):
                detected_wafs.add(waf_name)

    if detected_wafs:
        waf_list = ", ".join(detected_wafs)
        findings.append(FindingData(
            issue=f"WAF Detected: {waf_list}",
            severity="INFO",
            category="waf",
            impact=f"The site is protected by {waf_list}. This improves security against common attacks.",
            recommendation="Ensure WAF rules are tuned to prevent bypasses.",
            affected_element="WAF Configuration",
            score_impact=0, # WAF is a GOOD thing!
            confidence="HIGH"
        ))
    
    return findings
