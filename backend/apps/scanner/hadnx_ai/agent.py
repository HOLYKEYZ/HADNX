"""
HADNX AI Pentester Agent

Main agent class that provides a high-level interface for autonomous penetration testing.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

from .pipeline import PentestPipeline, PipelinePhase
from .ai_adapter import AIAdapter, AdapterFactory
from .prompt_loader import PromptLoader

logger = logging.getLogger(__name__)


class HADNXAgent:
    """
    Autonomous AI-powered penetration testing agent.
    
    Implements Shannon-style methodology:
    - Multi-stage pipeline execution
    - Backward taint analysis for vulnerability detection
    - Proof-based exploitation requirements
    - Structured deliverables and reporting
    """
    
    def __init__(self, adapter: Optional[AIAdapter] = None):
        """
        Initialize the HADNX AI Agent.
        
        Args:
            adapter: Optional pre-configured AI adapter
        """
        self.adapter = adapter
        self._pipeline: Optional[PentestPipeline] = None
    
    def _get_adapter(self) -> AIAdapter:
        """Get or create an AI adapter."""
        if self.adapter is None:
            self.adapter = AdapterFactory.create_pentest_adapter()
        return self.adapter
    
    def audit(self, target_url: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Run a full security audit on the target.
        
        This executes the complete pipeline:
        1. Reconnaissance - Map attack surface
        2. Vulnerability Analysis - XSS, Injection, Auth, AuthZ, SSRF
        3. Exploitation - Generate proof-of-concept payloads
        4. Reporting - Create executive summary
        
        Args:
            target_url: Target URL to audit
            context: Optional additional context (scan data, user info, etc.)
            
        Returns:
            Dict containing audit results, findings, and report
        """
        logger.info(f"Starting HADNX AI audit on {target_url}")
        
        try:
            self._pipeline = PentestPipeline(adapter=self._get_adapter())
            results = self._pipeline.run(target_url)
            
            # Add context info
            results["agent"] = "HADNX AI Pentester"
            results["version"] = "1.0.0"
            results["context"] = context or {}
            
            return results
            
        except Exception as e:
            logger.exception(f"Audit failed: {e}")
            return {
                "error": str(e),
                "target": target_url,
                "agent": "HADNX AI Pentester",
                "status": "failed",
            }
    
    def quick_scan(self, target_url: str, vuln_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run a quick vulnerability scan (no exploitation).
        
        Args:
            target_url: Target URL to scan
            vuln_types: List of vulnerability types to check ('xss', 'injection', 'auth', 'authz', 'ssrf')
            
        Returns:
            Dict containing findings
        """
        phases = [PipelinePhase.RECON]
        
        # Map vuln types to phases
        type_map = {
            'xss': PipelinePhase.VULN_XSS,
            'injection': PipelinePhase.VULN_INJECTION,
            'auth': PipelinePhase.VULN_AUTH,
            'authz': PipelinePhase.VULN_AUTHZ,
            'ssrf': PipelinePhase.VULN_SSRF,
        }
        
        if vuln_types:
            for vt in vuln_types:
                if vt.lower() in type_map:
                    phases.append(type_map[vt.lower()])
        else:
            # Default: all vuln types
            phases.extend([
                PipelinePhase.VULN_XSS,
                PipelinePhase.VULN_INJECTION,
                PipelinePhase.VULN_AUTH,
                PipelinePhase.VULN_AUTHZ,
                PipelinePhase.VULN_SSRF,
            ])
        
        self._pipeline = PentestPipeline(adapter=self._get_adapter())
        return self._pipeline.run(target_url, phases=phases)
    
    def exploit(self, target_url: str, finding_id: str) -> Dict[str, Any]:
        """
        Attempt to exploit a specific finding.
        
        Args:
            target_url: Target URL
            finding_id: ID of the finding to exploit
            
        Returns:
            Dict containing exploitation result
        """
        adapter = self._get_adapter()
        
        variables = {
            "WEB_URL": target_url,
            "FINDING_ID": finding_id,
        }
        
        prompt = PromptLoader.compose(
            "shared/_target",
            "shared/_exploit-scope",
            "exploit",
            variables=variables
        )
        
        try:
            response = adapter.generate_content(prompt)
            return {
                "finding_id": finding_id,
                "target": target_url,
                "result": response,
                "status": "completed",
            }
        except Exception as e:
            return {
                "finding_id": finding_id,
                "target": target_url,
                "error": str(e),
                "status": "failed",
            }
    
    def generate_report(self, results: Dict[str, Any]) -> str:
        """
        Generate an executive report from scan results.
        
        Args:
            results: Results from audit() or quick_scan()
            
        Returns:
            Markdown formatted executive report
        """
        adapter = self._get_adapter()
        
        variables = {
            "WEB_URL": results.get("target", "Unknown"),
            "FINDINGS_SUMMARY": self._format_findings(results.get("findings", [])),
            "SCAN_DATE": results.get("completed_at", datetime.now().isoformat()),
        }
        
        prompt = PromptLoader.load("report", variables=variables)
        return adapter.generate_content(prompt)
    
    def _format_findings(self, findings: List[Dict]) -> str:
        """Format findings for report generation."""
        if not findings:
            return "No vulnerabilities were identified."
        
        lines = []
        for f in findings:
            lines.append(
                f"- [{f.get('severity', 'unknown').upper()}] {f.get('title', 'Unknown finding')} "
                f"({f.get('type', 'unknown')})"
            )
        
        return "\n".join(lines)
    
    def get_logs(self) -> List[str]:
        """Get pipeline execution logs."""
        if self._pipeline and self._pipeline.context:
            return self._pipeline.context.logs
        return []
    
    @staticmethod
    def health_check() -> Dict[str, Any]:
        """
        Check if the agent is properly configured.
        
        Returns:
            Dict with health status
        """
        from ..services.key_manager import KeyManager
        
        checks = {
            "prompts_available": False,
            "gemini_key": False,
            "groq_key": False,
        }
        
        # Check prompts
        prompts = PromptLoader.list_prompts()
        checks["prompts_available"] = len(prompts) > 0
        checks["prompts_count"] = len(prompts)
        
        # Check keys
        key, provider = KeyManager.get_pentest_key()
        if key:
            if provider == 'gemini':
                checks["gemini_key"] = True
            elif provider == 'groq':
                checks["groq_key"] = True
        
        consulting_key = KeyManager.get_consulting_key()
        if consulting_key:
            checks["gemini_key"] = True
        
        checks["healthy"] = checks["prompts_available"] and (checks["gemini_key"] or checks["groq_key"])
        
        return checks
