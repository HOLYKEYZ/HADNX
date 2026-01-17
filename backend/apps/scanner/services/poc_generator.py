"""
PoC Generator Service.
Generates safe Proof-of-Concept commands for verifying vulnerabilities.
"""
from typing import List, Dict, Any

class PoCGenerator:
    """
    Generates reproduction steps (PoCs) for findings.
    """
    
    @staticmethod
    def generate_poc(finding: Dict[str, Any], url: str) -> str:
        """
        Generate a PoC command or script for a specific finding.
        """
        issue = finding.get('issue', '').lower()
        
        # 1. Missing Headers (General)
        if 'missing' in issue and 'header' in issue:
            header_name = finding.get('affected_element', '').split(':')[0]
            return f"# Verify missing header\ncurl -I -X GET {url} | grep -i '{header_name}'\n# Expected output: Nothing (header is missing)"

        # 2. Exposed Sensitive Files (.env, git, etc)
        if 'exposed' in issue and ('file' in issue or 'panel' in issue):
            path = finding.get('affected_element', '')
            target = f"{url.rstrip('/')}/{path}"
            return f"# Verify exposed file\ncurl -I -X GET {target}\n# Expected output: HTTP 200 OK"

        # 3. Open S3 Bucket
        if 's3 bucket' in issue:
             bucket_url = finding.get('affected_element', '').split(' ')[0]
             return f"# Verify open bucket\ncurl -I -X GET {bucket_url}\n# Expected output: HTTP 200 OK"
             
        # 4. Weak HSTS
        if 'hsts' in issue:
            return f"# Verify HSTS max-age\ncurl -I {url} | grep -i 'Strict-Transport-Security'\n# Check if max-age is < 31536000"

        # Default fallback
        return "# No automated PoC available for this finding type.\n# Please verify manually."

def attach_pocs(findings: List[Dict[str, Any]], url: str) -> List[Dict[str, Any]]:
    """
    Augment findings with a 'poc' field.
    """
    for f in findings:
        f['poc'] = PoCGenerator.generate_poc(f, url)
    return findings
