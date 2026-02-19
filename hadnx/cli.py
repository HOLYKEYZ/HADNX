#!/usr/bin/env python3
"""
Hadnx CLI - Web Security Posture Analysis from Terminal
"""
import sys
import os
import json
import click
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from typing import List, Dict, Any

try:
    from apps.scanner.services.core import fetch_url
    from apps.scanner.services.header_analyzer import analyze_headers, get_header_score
    from apps.scanner.services.cookie_analyzer import analyze_cookies, get_cookie_score
    from apps.scanner.services.tls_analyzer import analyze_tls
    from apps.scanner.services.scoring_engine import calculate_scores, get_score_breakdown, get_grade
    from apps.scanner.services.waf_detector import detect_waf
    from apps.scanner.services.mixed_content import analyze_mixed_content
    from apps.scanner.services.recon import SubdomainScanner
    from apps.scanner.services.cloud_recon import CloudReconScanner
    from apps.scanner.services.threat_intel import ThreatIntelScanner
    from apps.scanner.services.malware_check import MalwareChecker
    from apps.scanner.services.directory_brute import DirectoryBruteForcer
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure you're running from the project root directory.")
    sys.exit(1)


def print_banner():
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║   ██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗   ██╗               ║
    ║   ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║   ██║               ║
    ║   ███████║███████║██║     █████╔╝ ██║   ██║               ║
    ║   ██╔══██║██╔══██║██║     ██╔═██╗ ██║   ██║               ║
    ║   ██║  ██║██║  ██║╚██████╗██║  ██╗╚██████╔╝               ║
    ║   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝                ║
    ║                                                           ║
    ║        Web Security Posture Analysis Platform             ║
    ║                    CLI v1.0.0                             ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    click.echo(click.style(banner, fg="cyan"))


def format_severity(severity: str) -> str:
    colors = {
        "CRITICAL": "red",
        "HIGH": "bright_red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "green",
    }
    color = colors.get(severity.upper(), "white")
    return click.style(f"[{severity}]", fg=color, bold=True)


def print_findings(findings: List[Any], verbose: bool = False):
    if not findings:
        click.echo(click.style("  No findings!", fg="green"))
        return

    for f in findings:
        if hasattr(f, 'to_dict'):
            finding = f.to_dict()
        else:
            finding = f if isinstance(f, dict) else {}
        
        severity = finding.get('severity', 'INFO')
        issue = finding.get('issue', 'Unknown issue')
        category = finding.get('category', 'general')
        
        click.echo(f"  {format_severity(severity)} {click.style(issue, bold=True)}")
        
        if verbose:
            if finding.get('impact'):
                click.echo(f"    Impact: {finding['impact']}")
            if finding.get('recommendation'):
                click.echo(f"    Fix: {finding['recommendation']}")
            if finding.get('affected_element'):
                click.echo(f"    Element: {finding['affected_element']}")
            click.echo()


def print_score_report(score_result, breakdown: Dict):
    grade = score_result.grade
    score = score_result.overall_score
    
    grade_color = "green" if grade in ["A+", "A", "B"] else "yellow" if grade in ["C", "D"] else "red"
    
    click.echo("\n" + "═" * 60)
    click.echo(click.style(f"  SECURITY SCORE: {score}/100  GRADE: {grade}", fg=grade_color, bold=True))
    click.echo("═" * 60)
    
    categories = breakdown.get('categories', {})
    click.echo(f"\n  {'Category':<25} {'Score':<10} {'Weight'}")
    click.echo("  " + "-" * 50)
    
    for cat, data in categories.items():
        cat_score = data.get('score', 0)
        weight = data.get('weight', '0%')
        label = data.get('label', cat.title())
        score_color = "green" if cat_score >= 80 else "yellow" if cat_score >= 60 else "red"
        click.echo(f"  {label:<25} {click.style(str(cat_score), fg=score_color):<10} {weight}")
    
    sev = breakdown.get('severity_distribution', {})
    click.echo(f"\n  {'Findings Summary':<25}")
    click.echo("  " + "-" * 50)
    if sev.get('critical', 0) > 0:
        click.echo(f"  Critical: {click.style(str(sev['critical']), fg='red', bold=True)}")
    if sev.get('high', 0) > 0:
        click.echo(f"  High:     {click.style(str(sev['high']), fg='bright_red')}")
    if sev.get('medium', 0) > 0:
        click.echo(f"  Medium:   {click.style(str(sev['medium']), fg='yellow')}")
    if sev.get('low', 0) > 0:
        click.echo(f"  Low:      {click.style(str(sev['low']), fg='blue')}")
    click.echo(f"  Total:    {sev.get('total', 0)}")
    click.echo()


@click.group(invoke_without_command=True)
@click.option('--version', '-v', is_flag=True, help='Show version')
@click.pass_context
def main(ctx, version):
    """Hadnx - Web Security Posture Analysis Platform CLI"""
    if version:
        click.echo("hadnx v1.0.0")
        return
    if ctx.invoked_subcommand is None:
        print_banner()
        click.echo(ctx.get_help())


@main.command()
@click.argument('url')
@click.option('--verbose', '-V', is_flag=True, help='Show detailed findings')
@click.option('--output', '-o', type=click.Path(), help='Save report to JSON file')
@click.option('--headers/--no-headers', default=True, help='Analyze HTTP headers')
@click.option('--cookies/--no-cookies', default=True, help='Analyze cookies')
@click.option('--tls/--no-tls', default=True, help='Analyze TLS/SSL')
@click.option('--waf/--no-waf', default=True, help='Detect WAF')
def scan(url, verbose, output, headers, cookies, tls, waf):
    """Run a full security scan on a URL."""
    print_banner()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    click.echo(click.style(f"\n[+] Scanning: {url}", fg="cyan", bold=True))
    click.echo("    " + "─" * 50)
    
    all_findings = []
    
    with click.progressbar(length=5, label='Scanning', show_eta=False) as bar:
        bar.update(0)
        click.echo(f"\n[1/5] Fetching URL...")
        
        response = fetch_url(url)
        if response.get('error'):
            click.echo(click.style(f"Error: {response['error']}", fg="red"))
            return
        
        bar.update(1)
        
        if headers:
            click.echo("[2/5] Analyzing HTTP headers...")
            header_findings = analyze_headers(response.get('headers', {}))
            all_findings.extend([f.to_dict() if hasattr(f, 'to_dict') else f for f in header_findings])
        else:
            click.echo("[2/5] Skipping header analysis...")
        
        bar.update(2)
        
        if cookies:
            click.echo("[3/5] Analyzing cookies...")
            cookie_findings = analyze_cookies(response.get('set_cookies', []))
            all_findings.extend([f.to_dict() if hasattr(f, 'to_dict') else f for f in cookie_findings])
        else:
            click.echo("[3/5] Skipping cookie analysis...")
        
        bar.update(3)
        
        if tls and url.startswith('https://'):
            click.echo("[4/5] Analyzing TLS/SSL...")
            tls_findings, tls_info = analyze_tls(url)
            all_findings.extend([f.to_dict() if hasattr(f, 'to_dict') else f for f in tls_findings])
        else:
            click.echo("[4/5] Skipping TLS analysis...")
        
        bar.update(4)
        
        if waf:
            click.echo("[5/5] Detecting WAF...")
            waf_findings = detect_waf(response.get('headers', {}), response.get('set_cookies', []))
            all_findings.extend([f.to_dict() if hasattr(f, 'to_dict') else f for f in waf_findings])
        else:
            click.echo("[5/5] Skipping WAF detection...")
        
        bar.update(5)
    
    score_result = calculate_scores(all_findings)
    breakdown = get_score_breakdown(score_result)
    
    print_score_report(score_result, breakdown)
    
    click.echo(click.style("\n[+] Detailed Findings:", fg="cyan", bold=True))
    print_findings(all_findings, verbose)
    
    if output:
        report = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "score": {
                "overall": score_result.overall_score,
                "grade": score_result.grade,
                "breakdown": breakdown
            },
            "findings": all_findings,
            "response_info": {
                "status_code": response.get('status_code'),
                "final_url": response.get('url'),
                "ssl_error": response.get('ssl_error')
            }
        }
        with open(output, 'w') as f:
            json.dump(report, f, indent=2)
        click.echo(click.style(f"\n[+] Report saved to: {output}", fg="green"))


@main.command()
@click.argument('url')
@click.option('--verbose', '-V', is_flag=True, help='Show detailed findings')
def headers(url, verbose):
    """Analyze HTTP security headers only."""
    print_banner()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    click.echo(click.style(f"\n[+] Analyzing headers: {url}", fg="cyan", bold=True))
    
    response = fetch_url(url)
    if response.get('error'):
        click.echo(click.style(f"Error: {response['error']}", fg="red"))
        return
    
    findings = analyze_headers(response.get('headers', {}))
    score = get_header_score(findings)
    
    click.echo(f"\n  Headers Score: {click.style(str(score), fg='green' if score >= 80 else 'yellow' if score >= 60 else 'red')}/100")
    click.echo(f"  Headers Found: {len(response.get('headers', {}))}")
    
    click.echo(click.style("\n[+] Security Header Findings:", fg="cyan"))
    print_findings(findings, verbose)


@main.command()
@click.argument('url')
@click.option('--verbose', '-V', is_flag=True, help='Show detailed findings')
def cookies(url, verbose):
    """Analyze cookie security only."""
    print_banner()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    click.echo(click.style(f"\n[+] Analyzing cookies: {url}", fg="cyan", bold=True))
    
    response = fetch_url(url)
    if response.get('error'):
        click.echo(click.style(f"Error: {response['error']}", fg="red"))
        return
    
    set_cookies = response.get('set_cookies', [])
    findings = analyze_cookies(set_cookies)
    score = get_cookie_score(findings)
    
    click.echo(f"\n  Cookies Score: {click.style(str(score), fg='green' if score >= 80 else 'yellow' if score >= 60 else 'red')}/100")
    click.echo(f"  Cookies Found: {len(set_cookies)}")
    
    click.echo(click.style("\n[+] Cookie Security Findings:", fg="cyan"))
    print_findings(findings, verbose)


@main.command()
@click.argument('url')
@click.option('--verbose', '-V', is_flag=True, help='Show detailed findings')
def tls(url, verbose):
    """Analyze TLS/SSL configuration only."""
    print_banner()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    if not url.startswith('https://'):
        click.echo(click.style("TLS analysis requires HTTPS URL", fg="red"))
        return
    
    click.echo(click.style(f"\n[+] Analyzing TLS/SSL: {url}", fg="cyan", bold=True))
    
    findings, tls_info = analyze_tls(url)
    
    click.echo(f"\n  TLS Version: {tls_info.version}")
    click.echo(f"  Cipher: {tls_info.cipher_name}")
    click.echo(f"  Certificate Issuer: {tls_info.cert_issuer}")
    click.echo(f"  Days Until Expiry: {tls_info.cert_days_remaining}")
    
    click.echo(click.style("\n[+] TLS/SSL Findings:", fg="cyan"))
    print_findings(findings, verbose)


@main.command()
@click.argument('domain')
@click.option('--passive/--active', default=True, help='Passive (CRT.sh) or active DNS scan')
@click.option('--output', '-o', type=click.Path(), help='Save results to file')
def subdomains(domain, passive, output):
    """Enumerate subdomains for a domain."""
    print_banner()
    
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    click.echo(click.style(f"\n[+] Enumerating subdomains: {domain}", fg="cyan", bold=True))
    
    scanner = SubdomainScanner()
    findings = scanner.run(domain)
    
    subdomain_list = sorted(list(scanner.found_subdomains))
    
    click.echo(f"\n  Found {click.style(str(len(subdomain_list)), fg='green', bold=True)} subdomains\n")
    
    for subdomain in subdomain_list[:50]:
        click.echo(f"    • {subdomain}")
    
    if len(subdomain_list) > 50:
        click.echo(f"    ... and {len(subdomain_list) - 50} more")
    
    if output:
        with open(output, 'w') as f:
            json.dump({
                "domain": domain,
                "subdomains": subdomain_list,
                "count": len(subdomain_list)
            }, f, indent=2)
        click.echo(click.style(f"\n[+] Results saved to: {output}", fg="green"))


@main.command()
@click.argument('domain')
@click.option('--output', '-o', type=click.Path(), help='Save results to file')
def cloud(domain, output):
    """Discover cloud resources (S3, Azure, GCS)."""
    print_banner()
    
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    click.echo(click.style(f"\n[+] Scanning cloud resources: {domain}", fg="cyan", bold=True))
    
    scanner = CloudReconScanner()
    findings = scanner.run(domain)
    
    click.echo(click.style("\n[+] Cloud Resource Findings:", fg="cyan"))
    print_findings(findings, verbose=True)
    
    if output:
        with open(output, 'w') as f:
            json.dump([f.to_dict() if hasattr(f, 'to_dict') else f for f in findings], f, indent=2)


@main.command()
@click.argument('domain')
def wafdetect(domain):
    """Detect Web Application Firewall."""
    print_banner()
    
    if not domain.startswith(('http://', 'https://')):
        domain = 'https://' + domain
    
    click.echo(click.style(f"\n[+] Detecting WAF: {domain}", fg="cyan", bold=True))
    
    response = fetch_url(domain)
    if response.get('error'):
        click.echo(click.style(f"Error: {response['error']}", fg="red"))
        return
    
    findings = detect_waf(response.get('headers', {}), response.get('set_cookies', []))
    
    if findings:
        click.echo(click.style("\n[+] WAF Detected:", fg="yellow"))
        for f in findings:
            finding = f.to_dict() if hasattr(f, 'to_dict') else f
            click.echo(f"  • {finding.get('affected_element', 'Unknown WAF')}")
    else:
        click.echo(click.style("\n[-] No WAF detected", fg="green"))


@main.command()
@click.argument('domain')
@click.option('--output', '-o', type=click.Path(), help='Save results to file')
def threat(domain, output):
    """Check threat intelligence for a domain."""
    print_banner()
    
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    click.echo(click.style(f"\n[+] Checking threat intelligence: {domain}", fg="cyan", bold=True))
    
    scanner = ThreatIntelScanner()
    findings = scanner.run(domain)
    
    click.echo(click.style("\n[+] Threat Intelligence Findings:", fg="cyan"))
    print_findings(findings, verbose=True)
    
    if output:
        with open(output, 'w') as f:
            json.dump([f.to_dict() if hasattr(f, 'to_dict') else f for f in findings], f, indent=2)


@main.command()
@click.argument('url')
@click.option('--wordlist', '-w', type=click.Path(exists=True), help='Custom wordlist file')
@click.option('--threads', '-t', default=10, help='Number of threads')
def brute(url, wordlist, threads):
    """Directory bruteforce scan."""
    print_banner()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    click.echo(click.style(f"\n[+] Directory bruteforce: {url}", fg="cyan", bold=True))
    
    bruteforcer = DirectoryBruteForcer()
    findings = bruteforcer.run(url, wordlist=wordlist, threads=threads)
    
    click.echo(click.style("\n[+] Discovered Paths:", fg="cyan"))
    for f in findings:
        finding = f.to_dict() if hasattr(f, 'to_dict') else f
        path = finding.get('affected_element', '')
        status = finding.get('evidence', '')
        click.echo(f"  [{status}] {path}")


@main.command()
@click.argument('url')
def malware(url):
    """Check domain for malware/phishing."""
    print_banner()
    
    domain = url.replace('http://', '').replace('https://', '').split('/')[0]
    
    click.echo(click.style(f"\n[+] Checking malware reputation: {domain}", fg="cyan", bold=True))
    
    checker = MalwareChecker()
    findings = checker.check(domain)
    
    click.echo(click.style("\n[+] Malware Check Results:", fg="cyan"))
    print_findings(findings, verbose=True)


@main.command()
@click.option('--host', default='127.0.0.1', help='Backend host')
@click.option('--port', default=9001, help='Backend port')
@click.option('--frontend', is_flag=True, help='Also start frontend')
def serve(host, port, frontend):
    """Start the Hadnx web server."""
    print_banner()
    
    import subprocess
    
    backend_dir = Path(__file__).parent.parent / "backend"
    
    click.echo(click.style(f"\n[+] Starting backend server on {host}:{port}", fg="cyan"))
    
    os.chdir(backend_dir)
    
    backend_cmd = f"python manage.py runserver {host}:{port}"
    
    if frontend:
        click.echo(click.style("[+] Also starting frontend...", fg="cyan"))
        frontend_dir = Path(__file__).parent.parent / "frontend"
        subprocess.Popen(["npm", "run", "dev"], cwd=frontend_dir, shell=True)
    
    os.system(backend_cmd)


if __name__ == "__main__":
    main()
