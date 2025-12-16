"""
Celery tasks for security scanning.
Orchestrates the full scan lifecycle: fetch, analyze, score, save.
"""
import logging
from datetime import datetime, timezone
from celery import shared_task
from django.conf import settings
import requests

from .models import Scan, Finding
from .services.header_analyzer import analyze_headers
from .services.cookie_analyzer import analyze_cookies, get_cookie_matrix
from .services.tls_analyzer import analyze_tls
from .services.mixed_content import analyze_https_posture
from .services.scoring_engine import calculate_scores

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def run_security_scan(self, scan_id: str):
    """
    Main task to run a complete security scan.
    
    Args:
        scan_id: UUID of the Scan record to process
    """
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        logger.error(f"Scan {scan_id} not found")
        return
    
    # Update status to running
    scan.status = Scan.Status.RUNNING
    scan.save(update_fields=['status'])
    
    try:
        # Step 1: Fetch the URL
        logger.info(f"Starting scan for {scan.url}")
        response_data = fetch_url(scan.url)
        
        if response_data.get('error'):
            scan.status = Scan.Status.FAILED
            scan.error_message = response_data['error']
            scan.completed_at = datetime.now(timezone.utc)
            scan.save()
            return
        
        # Store response headers for reference
        scan.response_headers = response_data.get('headers', {})
        
        # Step 2: Run all analyzers
        all_findings = []
        
        # Header analysis
        logger.info("Analyzing HTTP headers...")
        header_findings = analyze_headers(response_data.get('headers', {}))
        all_findings.extend([f.to_dict() for f in header_findings])
        
        # Cookie analysis
        logger.info("Analyzing cookies...")
        set_cookies = response_data.get('set_cookies', [])
        is_https = scan.url.startswith('https://')
        cookie_findings = analyze_cookies(set_cookies, is_https)
        all_findings.extend([f.to_dict() for f in cookie_findings])
        
        # TLS analysis (only for HTTPS)
        if is_https:
            logger.info("Analyzing TLS configuration...")
            tls_findings, tls_info = analyze_tls(scan.url)
            all_findings.extend([f.to_dict() for f in tls_findings])
        
        # HTTPS posture analysis
        logger.info("Analyzing HTTPS enforcement...")
        html_content = response_data.get('html', '')
        https_findings = analyze_https_posture(scan.url, html_content)
        all_findings.extend([f.to_dict() for f in https_findings])
        
        # Step 3: Calculate scores
        logger.info("Calculating security scores...")
        scores = calculate_scores(all_findings)
        
        # Step 4: Save findings
        logger.info(f"Saving {len(all_findings)} findings...")
        for finding_data in all_findings:
            Finding.objects.create(
                scan=scan,
                issue=finding_data['issue'],
                description=finding_data.get('description', ''),
                severity=finding_data['severity'],
                category=finding_data['category'],
                impact=finding_data['impact'],
                recommendation=finding_data['recommendation'],
                fix_examples=finding_data.get('fix_examples', {}),
                affected_element=finding_data.get('affected_element', ''),
                score_impact=finding_data.get('score_impact', 0),
            )
        
        # Step 5: Update scan with results
        scan.overall_score = scores.overall_score
        scan.grade = scores.grade
        scan.headers_score = scores.headers_score
        scan.cookies_score = scores.cookies_score
        scan.tls_score = scores.tls_score
        scan.https_score = scores.https_score
        scan.status = Scan.Status.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.save()
        
        logger.info(f"Scan completed: {scan.url} - Score: {scores.overall_score} ({scores.grade})")
        
    except Exception as e:
        logger.exception(f"Scan failed for {scan.url}: {str(e)}")
        scan.status = Scan.Status.FAILED
        scan.error_message = str(e)
        scan.completed_at = datetime.now(timezone.utc)
        scan.save()
        
        # Retry on transient errors
        if self.request.retries < self.max_retries:
            raise self.retry(exc=e)


def fetch_url(url: str) -> dict:
    """
    Fetch URL and collect response data for analysis.
    
    Args:
        url: URL to fetch
    
    Returns:
        Dictionary with headers, cookies, html, and any errors
    """
    timeout = getattr(settings, 'SCAN_TIMEOUT', 30)
    max_redirects = getattr(settings, 'SCAN_MAX_REDIRECTS', 5)
    
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={
                'User-Agent': 'Hadnx Security Scanner/1.0 (https://hadnx.dev)',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            },
            verify=True,  # Verify SSL certificates
        )
        
        # Check redirect count
        if len(response.history) > max_redirects:
            return {'error': f'Too many redirects (>{max_redirects})'}
        
        # Collect headers (normalize to dict)
        headers = dict(response.headers)
        
        # Collect Set-Cookie headers (multiple values possible)
        set_cookies = []
        for cookie in response.cookies:
            # Reconstruct Set-Cookie header format
            cookie_str = f"{cookie.name}={cookie.value}"
            if cookie.secure:
                cookie_str += "; Secure"
            if 'httponly' in cookie._rest:
                cookie_str += "; HttpOnly"
            if cookie.path:
                cookie_str += f"; Path={cookie.path}"
            if cookie.domain:
                cookie_str += f"; Domain={cookie.domain}"
            if cookie.expires:
                cookie_str += f"; Expires={cookie.expires}"
            set_cookies.append(cookie_str)
        
        # Also check raw Set-Cookie headers
        raw_cookies = response.headers.get('Set-Cookie', '')
        if raw_cookies and not set_cookies:
            set_cookies = [raw_cookies]
        
        # Get HTML content (limit size)
        html = ''
        content_type = response.headers.get('Content-Type', '')
        if 'text/html' in content_type:
            # Limit to 1MB to avoid memory issues
            html = response.text[:1024 * 1024]
        
        return {
            'headers': headers,
            'set_cookies': set_cookies,
            'html': html,
            'status_code': response.status_code,
            'final_url': response.url,
        }
        
    except requests.exceptions.SSLError as e:
        return {'error': f'SSL Error: {str(e)}'}
    except requests.exceptions.ConnectionError as e:
        return {'error': f'Connection Error: Could not connect to {url}'}
    except requests.exceptions.Timeout:
        return {'error': f'Timeout: Request took longer than {timeout} seconds'}
    except requests.exceptions.TooManyRedirects:
        return {'error': 'Too many redirects'}
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}
