"""
TLS/SSL Configuration Analyzer.
Analyzes TLS version, cipher suites, and certificate configuration.
"""
import ssl
import socket
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


@dataclass
class FindingData:
    """Data structure for a security finding."""
    issue: str
    severity: str
    category: str = 'tls'
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


@dataclass
class TLSInfo:
    """TLS connection information."""
    version: str = ''
    cipher_name: str = ''
    cipher_bits: int = 0
    cert_subject: str = ''
    cert_issuer: str = ''
    cert_not_before: Optional[datetime] = None
    cert_not_after: Optional[datetime] = None
    cert_days_remaining: int = 0
    cert_san: List[str] = field(default_factory=list)


# Weak cipher patterns to flag
WEAK_CIPHERS = [
    'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon', 'ADH', 'AECDH'
]

# Minimum acceptable TLS version
MIN_TLS_VERSION = 'TLSv1.2'

# TLS version security ratings
TLS_VERSIONS = {
    'SSLv2': {'severity': 'CRITICAL', 'score_impact': 20},
    'SSLv3': {'severity': 'CRITICAL', 'score_impact': 20},
    'TLSv1': {'severity': 'HIGH', 'score_impact': 15},
    'TLSv1.0': {'severity': 'HIGH', 'score_impact': 15},
    'TLSv1.1': {'severity': 'HIGH', 'score_impact': 12},
    'TLSv1.2': {'severity': None, 'score_impact': 0},  # Acceptable
    'TLSv1.3': {'severity': None, 'score_impact': 0},  # Best
}


def analyze_tls(url: str, timeout: int = 10) -> tuple[List[FindingData], TLSInfo]:
    """
    Analyze TLS/SSL configuration for a URL.
    
    Args:
        url: The URL to analyze
        timeout: Connection timeout in seconds
    
    Returns:
        Tuple of (findings list, TLS info)
    """
    findings: List[FindingData] = []
    tls_info = TLSInfo()
    
    parsed = urlparse(url)
    hostname = parsed.netloc
    port = 443
    
    # Handle explicit port in URL
    if ':' in hostname:
        hostname, port_str = hostname.rsplit(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            port = 443
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get TLS version
                tls_info.version = ssock.version()
                
                # Get cipher info
                cipher = ssock.cipher()
                if cipher:
                    tls_info.cipher_name = cipher[0]
                    tls_info.cipher_bits = cipher[2]
                
                # Get certificate info
                cert_binary = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()
                
                if cert_dict:
                    # Parse subject
                    subject = cert_dict.get('subject', ())
                    for item in subject:
                        for k, v in item:
                            if k == 'commonName':
                                tls_info.cert_subject = v
                                break
                    
                    # Parse issuer
                    issuer = cert_dict.get('issuer', ())
                    for item in issuer:
                        for k, v in item:
                            if k == 'organizationName':
                                tls_info.cert_issuer = v
                                break
                    
                    # Parse validity dates
                    not_before = cert_dict.get('notBefore')
                    not_after = cert_dict.get('notAfter')
                    
                    if not_before:
                        tls_info.cert_not_before = _parse_cert_date(not_before)
                    if not_after:
                        tls_info.cert_not_after = _parse_cert_date(not_after)
                        if tls_info.cert_not_after:
                            tls_info.cert_days_remaining = (tls_info.cert_not_after - datetime.now(timezone.utc)).days
                    
                    # Parse SAN
                    san = cert_dict.get('subjectAltName', ())
                    tls_info.cert_san = [v for t, v in san if t == 'DNS']
        
        # Analyze TLS version
        version_finding = _check_tls_version(tls_info.version)
        if version_finding:
            findings.append(version_finding)
        
        # Analyze cipher strength
        cipher_findings = _check_cipher(tls_info.cipher_name, tls_info.cipher_bits)
        findings.extend(cipher_findings)
        
        # Analyze certificate
        cert_findings = _check_certificate(tls_info)
        findings.extend(cert_findings)
        
    except ssl.SSLCertVerificationError as e:
        findings.append(FindingData(
            issue="SSL Certificate Verification Failed",
            severity='CRITICAL',
            category='tls',
            impact=f"The SSL certificate could not be verified: {str(e)}. This may indicate an expired, self-signed, or misconfigured certificate.",
            recommendation="Ensure you have a valid certificate from a trusted Certificate Authority (CA).",
            fix_examples={
                'general': "1. Obtain a certificate from a trusted CA (e.g., Let's Encrypt)\n2. Ensure the certificate chain is complete\n3. Verify the certificate matches the domain",
                'letsencrypt': "# Install certbot and obtain free certificate:\nsudo certbot --nginx -d yourdomain.com",
            },
            affected_element=str(e),
            score_impact=20
        ))
    except ssl.SSLError as e:
        findings.append(FindingData(
            issue="SSL/TLS Connection Error",
            severity='HIGH',
            category='tls',
            impact=f"Could not establish secure connection: {str(e)}",
            recommendation="Check SSL/TLS configuration on your server.",
            fix_examples={
                'general': "Verify your SSL configuration using: openssl s_client -connect yourdomain.com:443",
            },
            affected_element=str(e),
            score_impact=15
        ))
    except socket.timeout:
        findings.append(FindingData(
            issue="TLS Connection Timeout",
            severity='MEDIUM',
            category='tls',
            impact="Could not complete TLS handshake within timeout period.",
            recommendation="Check server availability and network configuration.",
            fix_examples={},
            affected_element="Connection timeout",
            score_impact=5
        ))
    except socket.gaierror as e:
        findings.append(FindingData(
            issue="DNS Resolution Failed",
            severity='HIGH',
            category='tls',
            impact=f"Could not resolve hostname: {str(e)}",
            recommendation="Verify the domain name is correct and DNS is properly configured.",
            fix_examples={},
            affected_element=hostname,
            score_impact=15
        ))
    except Exception as e:
        findings.append(FindingData(
            issue="TLS Analysis Error",
            severity='MEDIUM',
            category='tls',
            impact=f"Unexpected error during TLS analysis: {str(e)}",
            recommendation="This may be a temporary issue. Try again later.",
            fix_examples={},
            affected_element=str(type(e).__name__),
            score_impact=5
        ))
    
    return findings, tls_info


def _parse_cert_date(date_str: str) -> Optional[datetime]:
    """Parse certificate date string to datetime."""
    try:
        # Format: 'May  1 00:00:00 2024 GMT'
        return datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            # Alternative format
            return datetime.strptime(date_str, '%b  %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        except ValueError:
            return None


def _check_tls_version(version: str) -> Optional[FindingData]:
    """Check if TLS version is acceptable."""
    if not version:
        return None
    
    config = TLS_VERSIONS.get(version)
    if config and config['severity']:
        return FindingData(
            issue=f"Outdated TLS Version: {version}",
            severity=config['severity'],
            category='tls',
            impact=f"{version} has known vulnerabilities and is no longer considered secure.",
            recommendation="Upgrade to TLS 1.2 or TLS 1.3.",
            fix_examples={
                'nginx': "ssl_protocols TLSv1.2 TLSv1.3;",
                'apache': "SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1",
                'general': "Disable all protocol versions below TLS 1.2 in your server configuration.",
            },
            affected_element=f"TLS Version: {version}",
            score_impact=config['score_impact']
        )
    return None


def _check_cipher(cipher_name: str, bits: int) -> List[FindingData]:
    """Check cipher suite strength."""
    findings = []
    
    if not cipher_name:
        return findings
    
    # Check for weak ciphers
    cipher_upper = cipher_name.upper()
    for weak in WEAK_CIPHERS:
        if weak.upper() in cipher_upper:
            findings.append(FindingData(
                issue=f"Weak Cipher Suite: {cipher_name}",
                severity='HIGH',
                category='tls',
                impact=f"The cipher suite '{cipher_name}' uses weak cryptography ({weak}) that can be exploited.",
                recommendation="Configure your server to use only strong cipher suites.",
                fix_examples={
                    'nginx': "ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';",
                    'apache': "SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
                    'general': "Use Mozilla's SSL Configuration Generator: https://ssl-config.mozilla.org/",
                },
                affected_element=f"Cipher: {cipher_name}",
                score_impact=12
            ))
            break
    
    # Check key length
    if bits < 128:
        findings.append(FindingData(
            issue=f"Weak Cipher Key Length: {bits} bits",
            severity='HIGH',
            category='tls',
            impact=f"A {bits}-bit key is too weak and can be brute-forced.",
            recommendation="Use cipher suites with at least 128-bit encryption (256-bit preferred).",
            fix_examples={
                'general': "Configure your server to use AES-128-GCM or AES-256-GCM cipher suites.",
            },
            affected_element=f"Key length: {bits} bits",
            score_impact=10
        ))
    
    return findings


def _check_certificate(tls_info: TLSInfo) -> List[FindingData]:
    """Check certificate configuration."""
    findings = []
    
    # Check expiration
    if tls_info.cert_days_remaining is not None:
        if tls_info.cert_days_remaining < 0:
            findings.append(FindingData(
                issue="SSL Certificate Expired",
                severity='CRITICAL',
                category='tls',
                impact=f"The SSL certificate expired {abs(tls_info.cert_days_remaining)} days ago. Browsers will show security warnings.",
                recommendation="Renew your SSL certificate immediately.",
                fix_examples={
                    'letsencrypt': "sudo certbot renew --force-renewal",
                    'general': "Contact your certificate authority to renew the certificate.",
                },
                affected_element=f"Expired on: {tls_info.cert_not_after}",
                score_impact=20
            ))
        elif tls_info.cert_days_remaining < 7:
            findings.append(FindingData(
                issue="SSL Certificate Expiring Very Soon",
                severity='HIGH',
                category='tls',
                impact=f"The SSL certificate expires in {tls_info.cert_days_remaining} days.",
                recommendation="Renew your SSL certificate as soon as possible.",
                fix_examples={
                    'letsencrypt': "sudo certbot renew",
                },
                affected_element=f"Expires on: {tls_info.cert_not_after}",
                score_impact=10
            ))
        elif tls_info.cert_days_remaining < 30:
            findings.append(FindingData(
                issue="SSL Certificate Expiring Soon",
                severity='MEDIUM',
                category='tls',
                impact=f"The SSL certificate expires in {tls_info.cert_days_remaining} days.",
                recommendation="Plan to renew your SSL certificate before expiration.",
                fix_examples={
                    'letsencrypt': "Set up automatic renewal: sudo certbot renew --dry-run",
                },
                affected_element=f"Expires on: {tls_info.cert_not_after}",
                score_impact=5
            ))
    
    return findings


def get_tls_score(findings: List[FindingData]) -> int:
    """Calculate TLS security score (0-100) based on findings."""
    max_score = 100
    total_impact = sum(f.score_impact for f in findings if f.category == 'tls')
    
    score = max(0, max_score - total_impact)
    return score
