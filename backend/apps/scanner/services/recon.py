"""
Reconnaissance Service.
Handles subdomain enumeration and asset discovery.
"""
import requests
import dns.resolver
import logging
import concurrent.futures
from typing import List, Dict, Any, Set
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)

@dataclass
class FindingData:
    """Data structure for a security finding."""
    issue: str
    severity: str
    category: str = 'recon'
    impact: str = ''
    recommendation: str = ''
    fix_examples: Dict[str, str] = field(default_factory=dict)
    affected_element: str = ''
    score_impact: int = 0
    # Phase 2 fields
    evidence: str = ''
    poc: str = ''
    confidence: str = 'HIGH'
    description: str = ''

# Common subdomains for active brute-forcing
COMMON_SUBDOMAINS = [
    'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
    'smtp', 'secure', 'vpn', 'm', 'shop', 'ftp', 'mail2', 'test',
    'portal', 'ns', 'ww1', 'host', 'support', 'dev', 'web', 'bbs',
    'ww42', 'mx', 'email', 'cloud', '1', 'mail1', '2', 'forum',
    'admin', 'api', 'stage', 'staging', 'beta', 'demo', 'app', 'apps'
]

class SubdomainScanner:
    """
    Scanner for discovering subdomains using passive and active methods.
    """
    
    def __init__(self):
        self.found_subdomains: Set[str] = set()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        # Use Google and Cloudflare DNS for reliability
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1']

    def run(self, domain: str) -> List[FindingData]:
        """
        Run full subdomain enumeration.
        """
        self.found_subdomains = set()
        logger.info(f"Starting subdomain enumeration for {domain}")
        
        # 1. Passive Scan (CRT.sh)
        self._scan_crtsh(domain)
        
        # 2. Active Scan (DNS Brute Force)
        self._scan_active_dns(domain)
        
        # 3. Generate Findings
        findings = []
        if self.found_subdomains:
            # Create a summary finding
            subdomain_list = sorted(list(self.found_subdomains))
            count = len(subdomain_list)
            
            # Truncate list for display if too long
            display_list = subdomain_list[:20]
            if count > 20:
                display_list.append(f"...and {count - 20} more")
            
            formatted_list = "\n".join([f"- {s}" for s in display_list])
            
            findings.append(FindingData(
                issue="Subdomains Discovered",
                severity="INFO",
                category="recon",
                impact=f"Found {count} accessible subdomains. These increases the attack surface.",
                recommendation="Review these subdomains. Ensure that development/staging environments (e.g., dev, test) are not publicly accessible or are properly secured.",
                fix_examples={
                    "General": "Audit DNS records and remove unused subdomains. Use VPN/Authentication for internal tools."
                },
                affected_element=f"{count} Subdomains",
                score_impact=0, # Info mapping generally doesn't lower score unless sensitive
                evidence=formatted_list
            ))
            
            # Check for sensitive subdomains
            sensitive_keywords = ['dev', 'stage', 'test', 'admin', 'beta', 'staging', 'internal']
            sensitive_found = [s for s in subdomain_list if any(k in s.split('.')[0] for k in sensitive_keywords)]
            
            if sensitive_found:
                findings.append(FindingData(
                    issue="Sensitive Subdomains Exposed",
                    severity="LOW",
                    category="recon",
                    impact=f"Potential development or administrative subdomains found: {', '.join(sensitive_found[:5])}. These often have weaker security controls.",
                    recommendation="Restrict access to these subdomains using IP allowlisting or VPN.",
                    affected_element=", ".join(sensitive_found[:5]),
                    score_impact=5
                ))

        return findings

    def _scan_crtsh(self, domain: str):
        """Query CRT.sh for subdomains."""
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    # CRT.sh returns multi-line entries sometimes
                    subdomains = name_value.split('\n')
                    for sub in subdomains:
                        sub = sub.strip().lower()
                        # Basic validation
                        if sub.endswith(domain) and '*' not in sub:
                            self.found_subdomains.add(sub)
            logger.info(f"CRT.sh found {len(self.found_subdomains)} subdomains")
        except Exception as e:
            logger.warning(f"CRT.sh scan failed: {str(e)}")

    def _scan_active_dns(self, domain: str):
        """Brute-force common subdomains."""
        
        def check_subdomain(sub):
            full_domain = f"{sub}.{domain}"
            try:
                # Just check if it resolves
                self.resolver.resolve(full_domain, 'A')
                return full_domain
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                return None
            except Exception:
                return None

        # Threaded resolution for speed
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_sub = {executor.submit(check_subdomain, sub): sub for sub in COMMON_SUBDOMAINS}
            for future in concurrent.futures.as_completed(future_to_sub):
                result = future.result()
                if result:
                    self.found_subdomains.add(result)
        
        logger.info(f"Active DNS finished. Total subdomains: {len(self.found_subdomains)}")

def run_recon_scan(domain: str) -> List[Dict[str, Any]]:
    """Helper to run scanner and return dicts."""
    scanner = SubdomainScanner()
    findings = scanner.run(domain)
    return [asdict(f) for f in findings]
