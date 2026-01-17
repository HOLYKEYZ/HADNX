"""
Mixed Content and HTTPS Enforcement Analyzer.
Checks for HTTP to HTTPS redirects, mixed content, and related security issues.
"""
import re
from typing import List, Dict, Any
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup


@dataclass
class FindingData:
    """Data structure for a security finding."""
    issue: str
    severity: str
    category: str = 'https'
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
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Elements that load external resources
RESOURCE_ELEMENTS = {
    'script': 'src',
    'link': 'href',
    'img': 'src',
    'iframe': 'src',
    'video': 'src',
    'audio': 'src',
    'source': 'src',
    'object': 'data',
    'embed': 'src',
    'form': 'action',
}

# CSS URL pattern
CSS_URL_PATTERN = re.compile(r'url\(["\']?(http://[^"\')\s]+)["\']?\)', re.IGNORECASE)


def check_https_redirect(url: str, timeout: int = 10) -> List[FindingData]:
    """
    Check if HTTP requests are properly redirected to HTTPS.
    
    Args:
        url: The URL to check
        timeout: Request timeout in seconds
    
    Returns:
        List of findings related to HTTPS enforcement
    """
    findings = []
    parsed = urlparse(url)
    
    # Only check if the original URL is HTTPS
    if parsed.scheme == 'https':
        # Try accessing the HTTP version
        http_url = url.replace('https://', 'http://', 1)
        
        try:
            response = requests.get(
                http_url,
                timeout=timeout,
                allow_redirects=False,
                headers={'User-Agent': 'Hadnx Security Scanner/1.0'}
            )
            
            if response.status_code in (301, 302, 307, 308):
                # Check if redirecting to HTTPS
                location = response.headers.get('Location', '')
                if location.startswith('https://'):
                    # Good - redirecting to HTTPS
                    if response.status_code == 302:
                        # 302 is temporary, should be 301 for permanent
                        findings.append(FindingData(
                            issue="HTTP to HTTPS redirect uses temporary redirect (302)",
                            severity='LOW',
                            category='https',
                            impact="Using 302 instead of 301 means search engines won't cache the redirect, and attackers could still attempt HTTP connections.",
                            recommendation="Use 301 (permanent) redirect instead of 302 (temporary) for HTTP to HTTPS.",
                            fix_examples={
                                'nginx': "server {\n    listen 80;\n    server_name example.com;\n    return 301 https://$server_name$request_uri;\n}",
                                'apache': "RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
                                'django': "# Use SECURE_SSL_REDIRECT = True in settings.py",
                            },
                            affected_element=f"302 redirect to {location}",
                            score_impact=2
                        ))
                else:
                    # Redirecting but not to HTTPS
                    findings.append(FindingData(
                        issue="HTTP redirect does not enforce HTTPS",
                        severity='HIGH',
                        category='https',
                        impact=f"HTTP requests redirect to {location} instead of HTTPS, leaving users vulnerable to man-in-the-middle attacks.",
                        recommendation="Configure redirects to always use HTTPS.",
                        fix_examples={
                            'nginx': "return 301 https://$server_name$request_uri;",
                            'apache': "RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
                        },
                        affected_element=f"Redirects to: {location}",
                        score_impact=10
                    ))
            else:
                # No redirect - HTTP accessible
                findings.append(FindingData(
                    issue="HTTP requests not redirected to HTTPS",
                    severity='HIGH',
                    category='https',
                    impact="The site is accessible over unencrypted HTTP, allowing attackers to intercept traffic.",
                    recommendation="Configure your server to redirect all HTTP requests to HTTPS.",
                    fix_examples={
                        'nginx': "server {\n    listen 80;\n    server_name example.com;\n    return 301 https://$server_name$request_uri;\n}",
                        'apache': "RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
                        'django': "# In settings.py:\nSECURE_SSL_REDIRECT = True",
                        'express': "app.use((req, res, next) => {\n  if (!req.secure) {\n    return res.redirect(301, 'https://' + req.headers.host + req.url);\n  }\n  next();\n});",
                    },
                    affected_element=f"HTTP status: {response.status_code}",
                    score_impact=12
                ))
        
        except requests.exceptions.SSLError:
            # HTTP connection established but with SSL issues (shouldn't happen on HTTP)
            pass
        except requests.exceptions.ConnectionError:
            # Could not connect to HTTP - this is fine if HTTP is completely disabled
            pass
        except requests.exceptions.Timeout:
            # Timeout on HTTP is acceptable
            pass
        except Exception:
            # Other errors - skip HTTP check
            pass
    
    return findings


def check_mixed_content(url: str, html_content: str) -> List[FindingData]:
    """
    Scan HTML content for mixed content (HTTP resources on HTTPS page).
    
    Args:
        url: The page URL (to check if HTTPS)
        html_content: The HTML content to scan
    
    Returns:
        List of mixed content findings
    """
    findings = []
    parsed = urlparse(url)
    
    # Only check for mixed content on HTTPS pages
    if parsed.scheme != 'https':
        return findings
    
    if not html_content:
        return findings
    
    soup = BeautifulSoup(html_content, 'lxml')
    mixed_active = []  # Scripts, iframes, etc. (high severity)
    mixed_passive = []  # Images, videos, etc. (lower severity)
    
    # Check each resource element
    for tag_name, attr_name in RESOURCE_ELEMENTS.items():
        for element in soup.find_all(tag_name):
            attr_value = element.get(attr_name, '')
            if attr_value and attr_value.startswith('http://'):
                resource_info = f"<{tag_name}> loading {attr_value[:100]}"
                
                # Active vs passive mixed content
                if tag_name in ('script', 'iframe', 'object', 'embed', 'form'):
                    mixed_active.append(resource_info)
                else:
                    mixed_passive.append(resource_info)
    
    # Check inline styles for http:// URLs
    for element in soup.find_all(style=True):
        style = element.get('style', '')
        http_urls = CSS_URL_PATTERN.findall(style)
        for http_url in http_urls:
            mixed_passive.append(f"Inline style loading {http_url[:100]}")
    
    # Check <style> tags
    for style_tag in soup.find_all('style'):
        if style_tag.string:
            http_urls = CSS_URL_PATTERN.findall(style_tag.string)
            for http_url in http_urls:
                mixed_passive.append(f"<style> loading {http_url[:100]}")
    
    # Report active mixed content (high severity)
    if mixed_active:
        findings.append(FindingData(
            issue="Active Mixed Content Detected",
            severity='HIGH',
            category='https',
            impact=f"Found {len(mixed_active)} HTTP resource(s) that could enable man-in-the-middle attacks. Active content (scripts, iframes) can execute malicious code.",
            recommendation="Update all resource URLs to use HTTPS or protocol-relative URLs.",
            fix_examples={
                'general': "Replace http:// with https:// or use protocol-relative URLs (//) for all resources.",
                'csp': "Add 'upgrade-insecure-requests' to Content-Security-Policy to automatically upgrade HTTP to HTTPS.",
            },
            affected_element='\n'.join(mixed_active[:5]) + (f'\n... and {len(mixed_active) - 5} more' if len(mixed_active) > 5 else ''),
            score_impact=12
        ))
    
    # Report passive mixed content (medium severity)
    if mixed_passive:
        findings.append(FindingData(
            issue="Passive Mixed Content Detected",
            severity='MEDIUM',
            category='https',
            impact=f"Found {len(mixed_passive)} HTTP resource(s). While less dangerous than scripts, these can still be intercepted or replaced.",
            recommendation="Update all resource URLs to use HTTPS.",
            fix_examples={
                'general': "Replace http:// with https:// for all images, stylesheets, and media.",
                'csp': "Content-Security-Policy: upgrade-insecure-requests;",
            },
            affected_element='\n'.join(mixed_passive[:5]) + (f'\n... and {len(mixed_passive) - 5} more' if len(mixed_passive) > 5 else ''),
            score_impact=6
        ))
    
    return findings


def analyze_https_posture(url: str, html_content: str = '', timeout: int = 10) -> List[FindingData]:
    """
    Complete HTTPS posture analysis.
    
    Args:
        url: The URL to analyze
        html_content: Optional HTML content for mixed content scanning
        timeout: Request timeout
    
    Returns:
        List of all HTTPS-related findings
    """
    findings = []
    
    # Check HTTPS redirect
    redirect_findings = check_https_redirect(url, timeout)
    findings.extend(redirect_findings)
    
    # Check for mixed content
    if html_content:
        mixed_findings = check_mixed_content(url, html_content)
        findings.extend(mixed_findings)
    
    return findings


def get_https_score(findings: List[FindingData]) -> int:
    """Calculate HTTPS enforcement score (0-100) based on findings."""
    max_score = 100
    total_impact = sum(f.score_impact for f in findings if f.category == 'https')
    
    score = max(0, max_score - total_impact)
    return score
