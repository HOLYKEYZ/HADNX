"""
Cloud Resource Discovery Service.
Checks for open cloud buckets and storage assets.
"""
import requests
import logging
import concurrent.futures
from typing import List, Dict, Any, Set
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse

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
    confidence: str = 'HIGH'
    evidence: str = ''
    poc: str = ''
    description: str = ''

class CloudScanner:
    """
    Scanner for discovering public cloud resources (S3, etc).
    """
    
    def __init__(self):
        self.found_buckets: List[str] = []
        # Common bucket mutations
        self.permutations = [
            '', 'dev', 'prod', 'test', 'staging', 'backup', 
            'assets', 'media', 'images', 'public', 'static',
            'www', 'app', 'db', 'logs'
        ]

    def run(self, domain_or_url: str) -> List[FindingData]:
        """
        Run cloud recon.
        """
        self.found_buckets = []
        
        # Extract base name (e.g., 'hadnx' from 'hadnx.com')
        try:
            if '://' in domain_or_url:
                hostname = urlparse(domain_or_url).netloc
            else:
                hostname = domain_or_url
            
            # Simple extraction: first part before dot (flawed but works for most recon)
            # Better: use tldextract if installed, but for now naive split
            parts = hostname.split('.')
            if len(parts) >= 2:
                base_name = parts[0]
                if base_name == 'www': 
                    base_name = parts[1]
            else:
                base_name = hostname
        except Exception:
            return []

        logger.info(f"Starting cloud recon for base name: {base_name}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_bucket = {}
            for perm in self.permutations:
                # Generate variations
                names = [
                    f"{base_name}{perm}",
                    f"{base_name}-{perm}",
                    f"{base_name}_{perm}"
                ] if perm else [base_name]

                for name in names:
                    future_to_bucket[executor.submit(self._check_s3, name)] = name
            
            for future in concurrent.futures.as_completed(future_to_bucket):
                result = future.result()
                if result:
                    self.found_buckets.append(result)

        return self._generate_findings()

    def _check_s3(self, bucket_name: str) -> str | None:
        """Check if S3 bucket exists and is accessible."""
        url = f"https://{bucket_name}.s3.amazonaws.com"
        try:
            resp = requests.head(url, timeout=3)
            # 200 = Open! 
            # 403 = Exists but private (Still a finding: Info Leak)
            # 404 = Doesn't exist
            if resp.status_code == 200:
                return f"{url} (OPEN - Publicly Accessible)"
            elif resp.status_code == 403:
                return f"{url} (EXISTS - Protected)"
            return None
        except:
            return None

    def _generate_findings(self) -> List[FindingData]:
        findings = []
        
        open_buckets = [b for b in self.found_buckets if "(OPEN" in b]
        protected_buckets = [b for b in self.found_buckets if "(EXISTS" in b]
        
        if open_buckets:
            findings.append(FindingData(
                issue="Open S3 Bucket Found",
                severity="CRITICAL",
                category="recon",
                impact="A public S3 bucket was found. Attackers can list, download, and potentially upload malicious files.",
                recommendation="Disable public access block on the bucket immediately and review bucket policies.",
                fix_examples={
                    "aws": "aws s3api put-public-access-block --bucket NAME --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                },
                affected_element="\n".join(open_buckets),
                score_impact=30
            ))
            
        elif protected_buckets:
             findings.append(FindingData(
                issue="Cloud Storage Bucket Detected",
                severity="INFO",
                category="recon",
                impact="Cloud storage buckets associated with this domain were found. They appear to be protected.",
                recommendation="Ensure these buckets are intended to be known. Private buckets should use random names to prevent enumeration.",
                affected_element="\n".join(protected_buckets),
                score_impact=0
            ))
            
        return findings

def run_cloud_scan(url: str) -> List[Dict[str, Any]]:
    scanner = CloudScanner()
    findings = scanner.run(url)
    return [asdict(f) for f in findings]
