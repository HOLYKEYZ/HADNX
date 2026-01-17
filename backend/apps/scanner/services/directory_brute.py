"""
Directory Bruteforce Service.
Discovers hidden files and directories using a curated wordlist.
"""
import requests
import logging
import concurrent.futures
from typing import List, Dict, Any
from dataclasses import dataclass, field, asdict
from urllib.parse import urljoin

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
    confidence: str = 'HIGH'

# Curated list of high-value targets (Short list for speed/safety)
COMMON_PATHS = [
    # Config & Secrets
    '.env', '.git/config', '.git/HEAD', '.svn/entries', '.ds_store',
    'config.php', 'wp-config.php', 'xmlrpc.php', 'composer.json', 'package.json',
    'docker-compose.yml', 'Dockerfile', 'robots.txt', 'sitemap.xml',
    
    # Admin Panels
    'admin', 'admin/', 'login', 'dashboard', 'panel', 'cpanel', 'whm',
    'administrator', 'wp-admin', 'phpmyadmin', 'sql', 'db',
    
    # Backups
    'backup', 'backup.sql', 'backup.zip', 'dump.sql', 'database.sql',
    'www.zip', 'site.zip', 'old', 'bak',
    
    # API & Dev
    'api', 'api/v1', 'v1', 'v2', 'graphql', 'swagger', 'test', 'dev',
    'staging', 'logs', 'error_log', 'access_log'
]

class DirectoryScanner:
    """
    Scanner for discovering hidden directories and files.
    """
    
    def __init__(self):
        self.found_paths: List[str] = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Hadnx Security Scanner/1.0 (https://hadnx.dev)'
        })

    def run(self, base_url: str) -> List[FindingData]:
        """
        Run directory bruteforce against the target.
        """
        self.found_paths = []
        logger.info(f"Starting directory bruteforce for {base_url}")
        
        # Normalize URL
        if not base_url.endswith('/'):
            base_url += '/'

        # Scan paths concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_path = {
                executor.submit(self._check_path, base_url, path): path 
                for path in COMMON_PATHS
            }
            
            for future in concurrent.futures.as_completed(future_to_path):
                result = future.result()
                if result:
                    self.found_paths.append(result)
        
        return self._generate_findings(base_url)

    def _check_path(self, base_url: str, path: str) -> str | None:
        """Check a single path."""
        url = urljoin(base_url, path)
        try:
            response = self.session.get(url, timeout=5, allow_redirects=False)
            
            # 200 OK = Definitely found
            if response.status_code == 200:
                # Filter out soft 404s (basic check)
                if len(response.content) < 500 or path in url: # basic heuristic
                    return path
            
            # 403 Forbidden = Exists but protected (Interested!)
            elif response.status_code == 403:
                return f"{path} (403 Forbidden)"
                
            # 301/302 Redirect = Often exists (e.g. /admin -> /admin/login)
            elif response.status_code in (301, 302):
                return f"{path} (Redirects)"
                
            return None
            
        except requests.RequestException:
            return None

    def _generate_findings(self, base_url: str) -> List[FindingData]:
        """Convert found paths to findings."""
        findings = []
        
        if not self.found_paths:
            return []
            
        # Group by type for cleaner reporting
        secrets = [p for p in self.found_paths if any(x in p for x in ['.env', '.git', 'config', 'json', 'yml'])]
        admins = [p for p in self.found_paths if any(x in p for x in ['admin', 'login', 'dashboard', 'panel'])]
        backups = [p for p in self.found_paths if any(x in p for x in ['backup', 'zip', 'sql', 'dump', 'bak'])]
        
        # 1. Exposed Secrets/Config (CRITICAL/HIGH)
        if secrets:
            findings.append(FindingData(
                issue="Sensitive Configuration Files Exposed",
                severity="CRITICAL",
                category="recon",
                impact="Exposed configuration files (.env, .git, etc.) often contain API keys, database credentials, or source code.",
                recommendation="Immediately deny access to these files via web server configuration (e.g., .htaccess or nginx location rules).",
                fix_examples={
                    "nginx": "location ~ /\\.(env|git|svn) { deny all; }",
                    "apache": "<FilesMatch \"^\\.(env|git|svn)\"> Order allow,deny Deny from all </FilesMatch>"
                },
                affected_element=", ".join(secrets),
                score_impact=25,
                confidence="HIGH"
            ))

        # 2. Exposed Admin Panels (MEDIUM)
        if admins:
            findings.append(FindingData(
                issue="Admin Panel Exposed",
                severity="MEDIUM",
                category="recon",
                impact="Administrative interfaces are exposed to the public internet, increasing the risk of brute-force attacks.",
                recommendation="Restrict access to admin panels to trusted IP addresses or require VPN access.",
                affected_element=", ".join(admins),
                score_impact=10
            ))

        # 3. Public Backups (HIGH)
        if backups:
            findings.append(FindingData(
                issue="Backup Files Exposed",
                severity="HIGH",
                category="recon",
                impact="Backup files often contain full source code or database dumps, leading to total system compromise.",
                recommendation="Remove backup files from the web root or ensure they are not accessible via HTTP.",
                affected_element=", ".join(backups),
                score_impact=20
            ))
            
        return findings

def run_directory_scan(url: str) -> List[Dict[str, Any]]:
    """Helper to run scanner and return dicts."""
    scanner = DirectoryScanner()
    findings = scanner.run(url)
    return [asdict(f) for f in findings]
