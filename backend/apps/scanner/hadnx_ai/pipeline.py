"""
Pipeline Orchestrator for HADNX AI Pentester

Implements the multi-stage penetration testing pipeline:
1. Recon - Attack surface mapping
2. Vulnerability Analysis - XSS, Injection, Auth, AuthZ, SSRF
3. Exploitation - Proof-based exploitation
4. Reporting - Executive summary generation
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

from .prompt_loader import PromptLoader
from .ai_adapter import AIAdapter, AdapterFactory

logger = logging.getLogger(__name__)


class PipelinePhase(Enum):
    """Pipeline execution phases."""
    RECON = "recon"
    VULN_XSS = "vuln_xss"
    VULN_INJECTION = "vuln_injection"
    VULN_AUTH = "vuln_auth"
    VULN_AUTHZ = "vuln_authz"
    VULN_SSRF = "vuln_ssrf"
    EXPLOIT = "exploit"
    REPORT = "report"


@dataclass
class Finding:
    """Represents a security finding."""
    id: str
    type: str  # xss, injection, auth, authz, ssrf
    severity: str  # critical, high, medium, low
    title: str
    description: str
    evidence: str
    confidence: str  # high, medium, low
    exploit_ready: bool = False
    exploit_payload: Optional[str] = None
    remediation: Optional[str] = None


@dataclass
class PipelineContext:
    """Shared context across pipeline stages."""
    target_url: str
    scan_id: Optional[str] = None
    started_at: datetime = field(default_factory=datetime.now)
    
    # Phase outputs
    recon_data: Optional[Dict] = None
    findings: List[Finding] = field(default_factory=list)
    exploited: List[Finding] = field(default_factory=list)
    
    # Progress tracking
    current_phase: Optional[PipelinePhase] = None
    completed_phases: List[PipelinePhase] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)
    
    def log(self, message: str):
        """Add a log entry."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.logs.append(f"[{timestamp}] {message}")
        logger.info(message)


class PentestPipeline:
    """
    Multi-stage penetration testing pipeline.
    
    Orchestrates the flow: Recon → Vuln Analysis → Exploitation → Report
    """
    
    def __init__(self, adapter: Optional[AIAdapter] = None):
        """
        Initialize the pipeline.
        
        Args:
            adapter: AI adapter for generating content. If None, creates one.
        """
        self.adapter = adapter or AdapterFactory.create_pentest_adapter()
        self.context: Optional[PipelineContext] = None
    
    def run(self, target_url: str, phases: Optional[List[PipelinePhase]] = None) -> Dict[str, Any]:
        """
        Run the full penetration testing pipeline.
        
        Args:
            target_url: Target URL to test
            phases: Optional list of specific phases to run
            
        Returns:
            Dict containing all findings and reports
        """
        self.context = PipelineContext(target_url=target_url)
        self.context.log(f"Starting HADNX AI Pentester on {target_url}")
        
        # Default: run all phases
        if phases is None:
            phases = [
                PipelinePhase.RECON,
                PipelinePhase.VULN_XSS,
                PipelinePhase.VULN_INJECTION,
                PipelinePhase.VULN_AUTH,
                PipelinePhase.VULN_AUTHZ,
                PipelinePhase.VULN_SSRF,
                PipelinePhase.EXPLOIT,
                PipelinePhase.REPORT,
            ]
        
        try:
            for phase in phases:
                self._run_phase(phase)
        except Exception as e:
            self.context.log(f"Pipeline error: {e}")
            logger.exception("Pipeline execution failed")
        
        return self._compile_results()
    
    def _run_phase(self, phase: PipelinePhase):
        """Run a single pipeline phase."""
        self.context.current_phase = phase
        self.context.log(f"Entering phase: {phase.value}")
        
        handlers = {
            PipelinePhase.RECON: self._phase_recon,
            PipelinePhase.VULN_XSS: self._phase_vuln_xss,
            PipelinePhase.VULN_INJECTION: self._phase_vuln_injection,
            PipelinePhase.VULN_AUTH: self._phase_vuln_auth,
            PipelinePhase.VULN_AUTHZ: self._phase_vuln_authz,
            PipelinePhase.VULN_SSRF: self._phase_vuln_ssrf,
            PipelinePhase.EXPLOIT: self._phase_exploit,
            PipelinePhase.REPORT: self._phase_report,
        }
        
        handler = handlers.get(phase)
        if handler:
            handler()
        
        self.context.completed_phases.append(phase)
        self.context.log(f"Completed phase: {phase.value}")
    
    def _phase_recon(self):
        """Execute reconnaissance phase."""
        variables = {"WEB_URL": self.context.target_url}
        
        prompt = PromptLoader.compose(
            "shared/_target",
            "shared/_vuln-scope",
            "recon",
            variables=variables
        )
        
        response = self.adapter.generate_content(prompt)
        
        # Parse recon data
        self.context.recon_data = {
            "raw": response,
            "target": self.context.target_url,
            "timestamp": datetime.now().isoformat(),
        }
        self.context.log("Reconnaissance complete - attack surface mapped")
    
    def _phase_vuln_xss(self):
        """Execute XSS vulnerability analysis."""
        self._run_vuln_analysis("vuln-xss", "xss")
    
    def _phase_vuln_injection(self):
        """Execute injection vulnerability analysis."""
        self._run_vuln_analysis("vuln-injection", "injection")
    
    def _phase_vuln_auth(self):
        """Execute authentication vulnerability analysis."""
        self._run_vuln_analysis("vuln-auth", "auth")
    
    def _phase_vuln_authz(self):
        """Execute authorization vulnerability analysis."""
        self._run_vuln_analysis("vuln-authz", "authz")
    
    def _phase_vuln_ssrf(self):
        """Execute SSRF vulnerability analysis."""
        self._run_vuln_analysis("vuln-ssrf", "ssrf")
    
    def _run_vuln_analysis(self, prompt_name: str, vuln_type: str):
        """Run a vulnerability analysis phase."""
        variables = {
            "WEB_URL": self.context.target_url,
            "RECON_DATA": self.context.recon_data.get("raw", "") if self.context.recon_data else "",
        }
        
        prompt = PromptLoader.compose(
            "shared/_target",
            "shared/_vuln-scope",
            prompt_name,
            variables=variables
        )
        
        response = self.adapter.generate_content(prompt)
        
        # Parse findings from response
        findings = self._parse_findings(response, vuln_type)
        self.context.findings.extend(findings)
        self.context.log(f"Found {len(findings)} potential {vuln_type} vulnerabilities")
    
    def _phase_exploit(self):
        """Execute exploitation phase."""
        variables = {
            "WEB_URL": self.context.target_url,
            "FINDINGS": self._format_findings_for_exploit(),
        }
        
        prompt = PromptLoader.compose(
            "shared/_target",
            "shared/_exploit-scope",
            "exploit",
            variables=variables
        )
        
        response = self.adapter.generate_content(prompt)
        
        # Parse exploited findings
        self._update_findings_with_exploits(response)
        exploited_count = len([f for f in self.context.findings if f.exploit_ready])
        self.context.log(f"Exploitation complete - {exploited_count} vulnerabilities confirmed")
    
    def _phase_report(self):
        """Generate executive report."""
        variables = {
            "WEB_URL": self.context.target_url,
            "FINDINGS_SUMMARY": self._format_findings_summary(),
            "RECON_SUMMARY": self.context.recon_data.get("raw", "")[:2000] if self.context.recon_data else "",
        }
        
        prompt = PromptLoader.load("report", variables=variables)
        response = self.adapter.generate_content(prompt)
        
        self.context.log("Executive report generated")
        return response
    
    def _parse_findings(self, response: str, vuln_type: str) -> List[Finding]:
        """Parse findings from AI response."""
        # This is a simplified parser - in production you'd use structured output
        findings = []
        
        # Look for vulnerability patterns in response
        if any(word in response.lower() for word in ['vulnerable', 'finding', 'issue', 'flaw']):
            finding = Finding(
                id=f"{vuln_type.upper()}-001",
                type=vuln_type,
                severity="medium",
                title=f"Potential {vuln_type.upper()} vulnerability detected",
                description=response[:500],
                evidence=response,
                confidence="medium",
            )
            findings.append(finding)
        
        return findings
    
    def _format_findings_for_exploit(self) -> str:
        """Format findings for exploitation prompt."""
        if not self.context.findings:
            return "No findings to exploit."
        
        lines = []
        for f in self.context.findings:
            lines.append(f"- [{f.id}] {f.title} (Severity: {f.severity}, Confidence: {f.confidence})")
        
        return "\n".join(lines)
    
    def _format_findings_summary(self) -> str:
        """Format findings for report."""
        if not self.context.findings:
            return "No vulnerabilities were identified during this assessment."
        
        by_severity = {"critical": [], "high": [], "medium": [], "low": []}
        for f in self.context.findings:
            by_severity.get(f.severity, []).append(f)
        
        lines = []
        for sev in ["critical", "high", "medium", "low"]:
            count = len(by_severity[sev])
            if count > 0:
                lines.append(f"- {sev.upper()}: {count} finding(s)")
        
        return "\n".join(lines) if lines else "No findings."
    
    def _update_findings_with_exploits(self, exploit_response: str):
        """Update findings with exploit information."""
        # Mark findings as exploited based on response
        if "exploited" in exploit_response.lower() or "confirmed" in exploit_response.lower():
            for finding in self.context.findings:
                finding.exploit_ready = True
                finding.exploit_payload = exploit_response[:1000]
    
    def _compile_results(self) -> Dict[str, Any]:
        """Compile final results."""
        return {
            "target": self.context.target_url,
            "started_at": self.context.started_at.isoformat(),
            "completed_at": datetime.now().isoformat(),
            "phases_completed": [p.value for p in self.context.completed_phases],
            "findings_count": len(self.context.findings),
            "exploited_count": len([f for f in self.context.findings if f.exploit_ready]),
            "findings": [
                {
                    "id": f.id,
                    "type": f.type,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "confidence": f.confidence,
                    "exploited": f.exploit_ready,
                }
                for f in self.context.findings
            ],
            "logs": self.context.logs,
            "recon_summary": self.context.recon_data.get("raw", "")[:2000] if self.context.recon_data else None,
        }
