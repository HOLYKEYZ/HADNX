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
    from apps.scanner.services.dos import DoSAttacker
    
    from apps.scanner.services.tools.nuclei_service import NucleiService
    from apps.scanner.services.tools.nmap_service import NmapService
    from apps.scanner.services.tools.sqlmap_service import SQLMapService
    from apps.scanner.services.tools.zap_service import ZapService
    from apps.scanner.services.tools.wireshark_service import WiresharkService
    
    from apps.scanner.services.exploit.xss_exploiter import AdvancedXSSExploiter, run_xss_exploitation
    from apps.scanner.services.exploit.sqli_exploiter import SQLiExploiter
    from apps.scanner.services.exploit.command_injection import CommandInjectionExploiter
    from apps.scanner.services.exploit.lfi_exploiter import LFIExploiter
    from apps.scanner.services.exploit.ssrf_exploiter import SSRFExploiter
    from apps.scanner.services.exploit.auth_bypass import AuthBypassTester
    from apps.scanner.services.exploit.file_upload import FileUploadExploiter
    
    from apps.scanner.hadnx_ai.agent import HADNXAgent
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


@main.group()
def ai():
    """AI-powered security testing commands."""
    pass


@ai.command()
@click.argument('url')
@click.option('--output', '-o', type=click.Path(), help='Save report to file')
@click.option('--quick', is_flag=True, help='Quick scan (no exploitation)')
def audit(url, output, quick):
    """Run autonomous AI pentest audit on target."""
    print_banner()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    click.echo(click.style(f"\n[+] Running AI Pentest Audit: {url}", fg="cyan", bold=True))
    click.echo(click.style("    This may take a few minutes...", fg="yellow"))
    
    agent = HADNXAgent()
    
    if quick:
        result = agent.quick_scan(url)
    else:
        result = agent.audit(url)
    
    if result.get('error'):
        click.echo(click.style(f"\n[!] Error: {result['error']}", fg="red"))
        return
    
    findings = result.get('findings', [])
    
    click.echo(f"\n  {click.style('AI Audit Complete', fg='green', bold=True)}")
    click.echo(f"  Target: {result.get('target', url)}")
    click.echo(f"  Findings: {len(findings)}")
    
    if findings:
        click.echo(click.style("\n[+] Vulnerabilities Found:", fg="cyan"))
        for f in findings:
            sev = f.get('severity', 'INFO').upper()
            title = f.get('title', f.get('type', 'Unknown'))
            click.echo(f"  {format_severity(sev)} {title}")
    
    if output:
        with open(output, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        click.echo(click.style(f"\n[+] Report saved to: {output}", fg="green"))


@ai.command()
def health():
    """Check AI agent health and configuration."""
    print_banner()
    
    click.echo(click.style("\n[+] Checking AI Agent Health...", fg="cyan"))
    
    health = HADNXAgent.health_check()
    
    status = "HEALTHY" if health.get('healthy') else "UNHEALTHY"
    color = "green" if health.get('healthy') else "red"
    
    click.echo(f"\n  Status: {click.style(status, fg=color, bold=True)}")
    click.echo(f"  Prompts Available: {health.get('prompts_available', False)}")
    click.echo(f"  Prompts Count: {health.get('prompts_count', 0)}")
    click.echo(f"  Gemini API Key: {'Set' if health.get('gemini_key') else 'Not Set'}")
    click.echo(f"  Groq API Key: {'Set' if health.get('groq_key') else 'Not Set'}")


@main.group()
def tools():
    """External security tool integrations."""
    pass


@tools.command()
@click.argument('url')
@click.option('--output', '-o', type=click.Path(), help='Save results to file')
def nuclei(url, output):
    """Run Nuclei vulnerability scanner."""
    print_banner()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    click.echo(click.style(f"\n[+] Running Nuclei scan: {url}", fg="cyan", bold=True))
    
    if not NucleiService.is_available():
        click.echo(click.style("[!] Nuclei not found. Install with:", fg="red"))
        click.echo("    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        return
    
    result = NucleiService.run_scan(url)
    
    if result.get('error'):
        click.echo(click.style(f"[!] Error: {result['error']}", fg="red"))
        return
    
    findings = result.get('findings', [])
    click.echo(f"\n  {click.style(str(result.get('count', 0)), fg='green')} findings\n")
    
    for f in findings[:20]:
        sev = f.get('info', {}).get('severity', 'unknown').upper()
        name = f.get('info', {}).get('name', 'Unknown')
        click.echo(f"  {format_severity(sev)} {name}")
    
    if len(findings) > 20:
        click.echo(f"  ... and {len(findings) - 20} more")
    
    if output:
        with open(output, 'w') as f:
            json.dump(result, f, indent=2)
        click.echo(click.style(f"\n[+] Results saved to: {output}", fg="green"))


@tools.command()
@click.argument('target')
@click.option('--ports', '-p', default='1-1000', help='Port range (e.g., 1-1000 or 80,443,8080)')
@click.option('--args', '-a', default='-sV -T4', help='Nmap arguments')
@click.option('--output', '-o', type=click.Path(), help='Save results to file')
def nmap(target, ports, args, output):
    """Run Nmap port scanner."""
    print_banner()
    
    click.echo(click.style(f"\n[+] Running Nmap scan: {target}", fg="cyan", bold=True))
    click.echo(f"    Ports: {ports}")
    
    if not NmapService.is_available():
        click.echo(click.style("[!] Nmap not found. Install from: https://nmap.org/download.html", fg="red"))
        return
    
    result = NmapService.run_scan(target, ports=ports, arguments=args)
    
    if result.get('error'):
        click.echo(click.style(f"[!] Error: {result['error']}", fg="red"))
        return
    
    for host in result.get('results', []):
        click.echo(f"\n  Host: {click.style(host['host'], fg='green')} ({host['state']})")
        for proto in host.get('protocols', []):
            click.echo(f"  Protocol: {proto['protocol']}")
            for port in proto.get('ports', []):
                state_color = "green" if port['state'] == 'open' else "yellow"
                click.echo(f"    {click.style(str(port['port']), fg=state_color)} {port['state']} {port['name']} {port.get('product', '')} {port.get('version', '')}")
    
    if output:
        with open(output, 'w') as f:
            json.dump(result, f, indent=2)
        click.echo(click.style(f"\n[+] Results saved to: {output}", fg="green"))


@tools.command()
@click.argument('url')
@click.option('--output', '-o', type=click.Path(), help='Save results to file')
def sqlmap(url, output):
    """Run SQLMap SQL injection scanner."""
    print_banner()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    click.echo(click.style(f"\n[+] Running SQLMap scan: {url}", fg="cyan", bold=True))
    click.echo(click.style("    This may take several minutes...", fg="yellow"))
    
    result = SQLMapService.run_scan(url)
    
    if result.get('error'):
        click.echo(click.style(f"[!] Error: {result['error']}", fg="red"))
        return
    
    if result.get('vulnerable'):
        click.echo(click.style("\n[!] SQL INJECTION VULNERABILITY DETECTED!", fg="red", bold=True))
    else:
        click.echo(click.style("\n[-] No SQL injection found", fg="green"))
    
    if output:
        with open(output, 'w') as f:
            json.dump(result, f, indent=2)
        click.echo(click.style(f"\n[+] Results saved to: {output}", fg="green"))


@tools.command()
@click.argument('url')
@click.option('--type', '-t', type=click.Choice(['spider', 'active', 'alerts']), default='spider', help='Scan type')
def zap(url, type):
    """Run OWASP ZAP scanner."""
    print_banner()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    conn = ZapService.check_connection()
    if not conn.get('connected'):
        click.echo(click.style("[!] Cannot connect to ZAP. Make sure ZAP is running on port 8080", fg="red"))
        return
    
    click.echo(click.style(f"\n[+] ZAP {type} scan: {url}", fg="cyan", bold=True))
    click.echo(f"    ZAP Version: {conn.get('version')}")
    
    if type == 'spider':
        result = ZapService.spider_scan(url)
    elif type == 'active':
        result = ZapService.active_scan(url)
    else:
        result = ZapService.get_alerts(url)
        alerts = result.get('alerts', [])
        click.echo(f"\n  {click.style(str(len(alerts)), fg='green')} alerts\n")
        for alert in alerts[:20]:
            sev = alert.get('risk', 'info').upper()
            click.echo(f"  {format_severity(sev)} {alert.get('name', 'Unknown')}")
        return
    
    if result.get('error'):
        click.echo(click.style(f"[!] Error: {result['error']}", fg="red"))
    else:
        click.echo(click.style(f"\n[+] Scan started: {result.get('scan_id')}", fg="green"))


@tools.command()
@click.option('--interface', '-i', default='eth0', help='Network interface')
@click.option('--duration', '-d', default=10, help='Capture duration in seconds')
@click.option('--output', '-o', type=click.Path(), help='Output pcap file')
def capture(interface, duration, output):
    """Capture network packets with Wireshark/Tshark."""
    print_banner()
    
    click.echo(click.style(f"\n[+] Starting packet capture", fg="cyan", bold=True))
    
    interfaces = WiresharkService.list_interfaces()
    if interfaces.get('interfaces'):
        click.echo("\n  Available interfaces:")
        for iface in interfaces['interfaces']:
            click.echo(f"    {iface['id']}: {iface['name']}")
    
    if not WiresharkService.is_available():
        click.echo(click.style("[!] Tshark not found. Install Wireshark.", fg="red"))
        return
    
    click.echo(f"\n  Capturing on {interface} for {duration}s...")
    
    result = WiresharkService.capture(interface=interface, duration=duration, filename=output)
    
    if result.get('error'):
        click.echo(click.style(f"[!] Error: {result['error']}", fg="red"))
    else:
        click.echo(click.style(f"\n[+] Capture saved to: {result['file']}", fg="green"))


@main.group()
def exploit():
    """Exploitation modules (requires authorization)."""
    pass


@exploit.command()
@click.argument('url')
@click.option('--deep', is_flag=True, help='Deep scan including forms')
@click.option('--output', '-o', type=click.Path(), help='Save results to file')
def xss(url, deep, output):
    """Test for XSS vulnerabilities."""
    print_banner()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    click.echo(click.style(f"\n[+] Testing XSS vulnerabilities: {url}", fg="cyan", bold=True))
    
    findings = run_xss_exploitation(url, deep=deep)
    
    if findings:
        click.echo(click.style(f"\n[!] {len(findings)} XSS vulnerabilities found!", fg="red", bold=True))
        for f in findings:
            click.echo(f"\n  {format_severity(f.get('severity', 'HIGH'))} {f.get('issue')}")
            click.echo(f"    Parameter: {f.get('affected_element')}")
            click.echo(f"    Technique: {f.get('description', '')[:100]}")
    else:
        click.echo(click.style("\n[-] No XSS vulnerabilities found", fg="green"))
    
    if output:
        with open(output, 'w') as f:
            json.dump(findings, f, indent=2)


@exploit.command()
@click.argument('url')
@click.option('--output', '-o', type=click.Path(), help='Save results to file')
def sqli(url, output):
    """Test for SQL injection vulnerabilities."""
    print_banner()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    click.echo(click.style(f"\n[+] Testing SQL injection: {url}", fg="cyan", bold=True))
    
    exploiter = SQLiExploiter()
    findings = exploiter.exploit(url)
    
    if findings:
        click.echo(click.style(f"\n[!] {len(findings)} SQL injection vulnerabilities found!", fg="red", bold=True))
        print_findings(findings, verbose=True)
    else:
        click.echo(click.style("\n[-] No SQL injection found", fg="green"))
    
    if output:
        with open(output, 'w') as f:
            json.dump(findings, f, indent=2, default=str)


@exploit.command()
@click.argument('url')
@click.option('--output', '-o', type=click.Path(), help='Save results to file')
def cmdi(url, output):
    """Test for command injection vulnerabilities."""
    print_banner()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    click.echo(click.style(f"\n[+] Testing command injection: {url}", fg="cyan", bold=True))
    
    exploiter = CommandInjectionExploiter()
    findings = exploiter.exploit(url)
    
    if findings:
        click.echo(click.style(f"\n[!] {len(findings)} command injection vulnerabilities found!", fg="red", bold=True))
        print_findings(findings, verbose=True)
    else:
        click.echo(click.style("\n[-] No command injection found", fg="green"))
    
    if output:
        with open(output, 'w') as f:
            json.dump(findings, f, indent=2, default=str)


@exploit.command()
@click.argument('url')
@click.option('--output', '-o', type=click.Path(), help='Save results to file')
def lfi(url, output):
    """Test for Local File Inclusion vulnerabilities."""
    print_banner()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    click.echo(click.style(f"\n[+] Testing LFI vulnerabilities: {url}", fg="cyan", bold=True))
    
    exploiter = LFIExploiter()
    findings = exploiter.exploit(url)
    
    if findings:
        click.echo(click.style(f"\n[!] {len(findings)} LFI vulnerabilities found!", fg="red", bold=True))
        print_findings(findings, verbose=True)
    else:
        click.echo(click.style("\n[-] No LFI found", fg="green"))
    
    if output:
        with open(output, 'w') as f:
            json.dump(findings, f, indent=2, default=str)


@exploit.command()
@click.argument('url')
@click.option('--output', '-o', type=click.Path(), help='Save results to file')
def ssrf(url, output):
    """Test for SSRF vulnerabilities."""
    print_banner()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    click.echo(click.style(f"\n[+] Testing SSRF vulnerabilities: {url}", fg="cyan", bold=True))
    
    exploiter = SSRFExploiter()
    findings = exploiter.exploit(url)
    
    if findings:
        click.echo(click.style(f"\n[!] {len(findings)} SSRF vulnerabilities found!", fg="red", bold=True))
        print_findings(findings, verbose=True)
    else:
        click.echo(click.style("\n[-] No SSRF found", fg="green"))
    
    if output:
        with open(output, 'w') as f:
            json.dump(findings, f, indent=2, default=str)


@exploit.command()
@click.argument('url')
@click.option('--output', '-o', type=click.Path(), help='Save results to file')
def auth(url, output):
    """Test for authentication bypass vulnerabilities."""
    print_banner()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    click.echo(click.style(f"\n[+] Testing authentication bypass: {url}", fg="cyan", bold=True))
    
    tester = AuthBypassTester()
    findings = tester.test(url)
    
    if findings:
        click.echo(click.style(f"\n[!] {len(findings)} auth bypass issues found!", fg="red", bold=True))
        print_findings(findings, verbose=True)
    else:
        click.echo(click.style("\n[-] No auth bypass found", fg="green"))
    
    if output:
        with open(output, 'w') as f:
            json.dump(findings, f, indent=2, default=str)


@exploit.command()
@click.argument('url')
@click.option('--output', '-o', type=click.Path(), help='Save results to file')
def upload(url, output):
    """Test for file upload vulnerabilities."""
    print_banner()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    click.echo(click.style(f"\n[+] Testing file upload vulnerabilities: {url}", fg="cyan", bold=True))
    
    exploiter = FileUploadExploiter()
    findings = exploiter.exploit(url)
    
    if findings:
        click.echo(click.style(f"\n[!] {len(findings)} file upload vulnerabilities found!", fg="red", bold=True))
        print_findings(findings, verbose=True)
    else:
        click.echo(click.style("\n[-] No file upload vulnerabilities found", fg="green"))
    
    if output:
        with open(output, 'w') as f:
            json.dump(findings, f, indent=2, default=str)


@main.command()
@click.argument('url')
@click.option('--method', '-m', type=click.Choice(['HTTP', 'SLOWLORIS']), default='HTTP', help='Attack method')
@click.option('--intensity', '-i', type=click.Choice(['low', 'medium', 'high']), default='low', help='Attack intensity')
@click.option('--duration', '-d', default=30, help='Duration in seconds (max 300)')
@click.option('--confirm', is_flag=True, help='Confirm you have authorization')
def dos(url, method, intensity, duration, confirm):
    """DoS/DDoS simulation (AUTHORIZED USE ONLY)."""
    print_banner()
    
    if not confirm:
        click.echo(click.style("\n[!] WARNING: This tool is for authorized testing only!", fg="red", bold=True))
        click.echo("    Use --confirm flag to acknowledge you have authorization.")
        return
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    click.echo(click.style(f"\n[!] DoS Simulation Mode", fg="red", bold=True))
    click.echo(click.style(f"    Target: {url}", fg="yellow"))
    click.echo(click.style(f"    Method: {method}", fg="yellow"))
    click.echo(click.style(f"    Intensity: {intensity}", fg="yellow"))
    click.echo(click.style(f"    Duration: {duration}s", fg="yellow"))
    
    if not click.confirm("\n    Continue with attack simulation?", default=False):
        click.echo("Aborted.")
        return
    
    attacker = DoSAttacker()
    result = attacker.start_attack(url, method=method, intensity=intensity, duration=duration)
    
    click.echo(click.style(f"\n[+] Attack started: {result['status']}", fg="green"))
    click.echo("    Press Ctrl+C to stop early")
    
    try:
        import time
        for i in range(int(duration)):
            time.sleep(1)
            click.echo(f"\r    Elapsed: {i+1}s / {duration}s", nl=False)
    except KeyboardInterrupt:
        attacker.stop_attack()
        click.echo(click.style("\n\n[+] Attack stopped by user", fg="yellow"))


if __name__ == "__main__":
    main()
