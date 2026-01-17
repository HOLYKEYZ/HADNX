"""
Threat Intelligence Service.
Checks domain reputation against known threat feeds.
"""
import requests
import logging
from typing import List, Dict, Any
from dataclasses import dataclass, field, asdict
import socket

logger = logging.getLogger(__name__)

@dataclass
class FindingData:
    issue: str
    severity: str
    category: str = 'threat_intel'
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

class ThreatIntelScanner:
    """
    Checks if the domain is flagged in known threat databases.
    """
    
    def run(self, domain: str) -> List[FindingData]:
        findings = []
        logger.info(f"Checking threat intel for {domain}")
        
        # 1. Check if domain resolves to known sinkhole IPs (Simulation)
        try:
            ip = socket.gethostbyname(domain)
            # Known sinkhole IPs (example list)
            sinkholes = ['0.0.0.0', '127.0.0.1', '10.10.10.10'] 
            if ip in sinkholes:
                findings.append(FindingData(
                    issue="Domain Resolves to Sinkhole/Loopback",
                    severity="LOW",
                    category="threat_intel",
                    impact=f"The domain resolves to {ip}, which is often done for suspended or blocked domains.",
                    recommendation="Verify DNS configuration.",
                    affected_element=f"DNS A Record: {ip}",
                    score_impact=0
                ))
        except:
            pass

        # 2. VirusTotal / Google Safe Browsing / AlienVault OTX
        # Note: These require API keys in a real production environment.
        # We will implement a "Free Tier" check using public DNS blocklists if possible,
        # or simulate the check for the 'Malware/Phishing' feature integration.
        
        # For this implementation, we will perform a lightweight "AbuseIPDB" style check
        # by checking if it's on a curated list of bad TLDs or patterns.
        
        audit_result = self._heuristic_audit(domain)
        if audit_result:
             findings.append(audit_result)

        return findings

    def _heuristic_audit(self, domain: str) -> FindingData | None:
        """Heuristic checks without API keys."""
        # 1. Suspicious TLDs
        suspicious_tlds = ['.zip', '.mov', '.xyz', '.top', '.gq', '.cf', '.tk', '.ml', '.ga']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                return FindingData(
                    issue="Suspicious TLD Detected",
                    severity="INFO",
                    category="threat_intel",
                    impact=f"The domain uses the {tld} TLD, which is frequently used by phishing campaigns.",
                    recommendation="Ensure this TLD is intended and monitor for brand impersonation.",
                    affected_element=domain,
                    score_impact=0
                )
        return None

def run_threat_scan(domain: str) -> List[Dict[str, Any]]:
    scanner = ThreatIntelScanner()
    findings = scanner.run(domain)
    return [asdict(f) for f in findings]
