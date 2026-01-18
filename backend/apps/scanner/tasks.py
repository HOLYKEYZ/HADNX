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
from .services.core import fetch_url
from .services.header_analyzer import analyze_headers
from .services.cookie_analyzer import analyze_cookies, get_cookie_matrix
from .services.tls_analyzer import analyze_tls
from .services.mixed_content import analyze_https_posture
from .services.scoring_engine import calculate_scores
from .services.recon import run_recon_scan
from .services.waf_detector import detect_waf
from .services.directory_brute import run_directory_scan

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
        
        # Check for SSL Error from fetch_url (captured during retry)
        if response_data.get('ssl_error'):
            logger.info("Reporting SSL Error as finding...")
            all_findings.append({
                'issue': 'SSL Certificate Verification Failed',
                'description': f"The server's SSL certificate could not be verified. Error: {response_data['ssl_error']}",
                'severity': 'CRITICAL',
                'category': 'tls',
                'impact': 'Users may be intercepted by attackers. The connection is not trustworthy.',
                'recommendation': 'Renew or fix the SSL certificate configuration immediately.',
                'affected_element': 'SSL/TLS Certificate',
                'score_impact': 100
            })

        # Reconnaissance (Subdomains) - Phase 2 Feature
        logger.info("Running reconnaissance...")
        recon_findings = run_recon_scan(scan.domain)
        # recon_findings are already dicts because run_recon_scan converts them
        all_findings.extend(recon_findings)

        # WAF Detection - Phase 2 Feature
        logger.info("Detecting WAF...")
        waf_findings = detect_waf(response_data.get('headers', {}), response_data.get('set_cookies', []))
        all_findings.extend([f.to_dict() for f in waf_findings])

        # Directory Bruteforce - Phase 2 Feature
        logger.info("Running directory bruteforce...")
        dir_findings = run_directory_scan(scan.url)
        all_findings.extend(dir_findings)

        # Cloud Recon - Phase 2 Feature
        logger.info("Running cloud resource discovery...")
        from .services.cloud_recon import run_cloud_scan
        cloud_findings = run_cloud_scan(scan.url)
        all_findings.extend(cloud_findings)

        # Threat Intel - Phase 2 Feature
        logger.info("Checking threat intelligence...")
        from .services.threat_intel import run_threat_scan
        threat_findings = run_threat_scan(scan.domain)
        all_findings.extend(threat_findings)

        # Malware/Phishing - Phase 2 Feature
        logger.info("Scanning for malware/phishing indicators...")
        from .services.malware_check import run_malware_scan
        malware_findings = run_malware_scan(scan.url, response_data.get('html', ''))
        all_findings.extend(malware_findings)

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

        # Generate PoCs (Exploitation Sandbox) - Phase 2 Feature
        from .services.poc_generator import attach_pocs
        all_findings = attach_pocs(all_findings, scan.url)

        # AI Pentest Analysis - Phase 2 Feature
        from .services.ai_agent import run_ai_analysis
        ai_report = run_ai_analysis(all_findings, scan.domain)
        
        # Append AI Report as a special finding
        all_findings.insert(0, { # Put at top
            'issue': "AI Pentest Assessment",
            'severity': "INFO",
            'category': "ai_analysis",
            'impact': ai_report['risk_assessment'],
            'description': ai_report['attack_narrative'],
            'recommendation': ai_report['next_steps'],
            'affected_element': "Entire Scope",
            'score_impact': 0
        })
        
        # Calculate scores
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



