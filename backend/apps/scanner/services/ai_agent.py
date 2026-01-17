"""
AI Pentest Agent Service.
Uses LLMs (Groq primary, Gemini fallback) to analyze scan findings and generate attack scenarios.
"""
from typing import List, Dict, Any
import os
import json
import logging
import requests

logger = logging.getLogger(__name__)

SECURITY_ANALYSIS_PROMPT = """You are an expert penetration tester AI assistant. Analyze the following security scan findings for the domain "{domain}" and provide a concise security assessment.

FINDINGS:
{findings_summary}

Respond in the following JSON format ONLY (no markdown, no extra text):
{{
    "attack_narrative": "A 2-3 sentence narrative describing the most likely attack path an attacker could take based on these findings.",
    "risk_assessment": "Critical|High|Medium|Low - one word",
    "next_steps": "Numbered list of 3-5 specific remediation steps"
}}"""


class AIPentestAgent:
    """
    Agentic AI that interprets security findings.
    Uses Groq (primary) -> Gemini (fallback) -> Simulation (final fallback)
    """
    
    def __init__(self):
        self.groq_key = os.environ.get('GROQ_KEY')
        self.gemini_key = os.environ.get('GEMINI_KEY')

    def analyze(self, findings: List[Dict[str, Any]], domain: str) -> Dict[str, str]:
        """
        Analyze findings and return an AI-generated report.
        """
        # Summarize findings for the prompt
        criticals = [f for f in findings if f.get('severity') == 'CRITICAL']
        highs = [f for f in findings if f.get('severity') == 'HIGH']
        mediums = [f for f in findings if f.get('severity') == 'MEDIUM']
        
        findings_summary = self._create_findings_summary(findings)
        prompt = SECURITY_ANALYSIS_PROMPT.format(domain=domain, findings_summary=findings_summary)
        
        # Try Groq first
        if self.groq_key:
            logger.info("Attempting AI analysis with Groq...")
            result = self._call_groq(prompt)
            if result:
                return result
        
        # Fallback to Gemini
        if self.gemini_key:
            logger.info("Falling back to Gemini for AI analysis...")
            result = self._call_gemini(prompt)
            if result:
                return result
        
        # Final fallback: Simulation
        logger.info("Using simulation mode for AI analysis (no API keys configured)")
        return self._simulate_analysis(len(criticals), len(highs), domain)

    def _create_findings_summary(self, findings: List[Dict[str, Any]]) -> str:
        """Create a concise summary of findings for the LLM prompt."""
        summary_lines = []
        for f in findings[:15]:  # Limit to 15 to avoid token overflow
            severity = f.get('severity', 'UNKNOWN')
            issue = f.get('issue', 'Unknown issue')
            category = f.get('category', 'general')
            summary_lines.append(f"- [{severity}] {issue} (Category: {category})")
        
        return "\n".join(summary_lines) if summary_lines else "No critical findings detected."

    def _call_groq(self, prompt: str) -> Dict[str, str] | None:
        """Call Groq API (uses OpenAI-compatible endpoint)."""
        try:
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.groq_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "llama-3.3-70b-versatile",
                    "messages": [
                        {"role": "system", "content": "You are an expert penetration tester. Respond only in valid JSON."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.3,
                    "max_tokens": 500
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                content = data['choices'][0]['message']['content']
                return self._parse_llm_response(content)
            else:
                logger.error(f"Groq API error: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Groq API call failed: {e}")
            return None

    def _call_gemini(self, prompt: str) -> Dict[str, str] | None:
        """Call Google Gemini API."""
        try:
            response = requests.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={self.gemini_key}",
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.3,
                        "maxOutputTokens": 500
                    }
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                content = data['candidates'][0]['content']['parts'][0]['text']
                return self._parse_llm_response(content)
            else:
                logger.error(f"Gemini API error: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Gemini API call failed: {e}")
            return None

    def _parse_llm_response(self, content: str) -> Dict[str, str] | None:
        """Parse JSON response from LLM."""
        try:
            # Clean up response (remove markdown code blocks if present)
            content = content.strip()
            if content.startswith("```json"):
                content = content[7:]
            if content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
            
            parsed = json.loads(content.strip())
            return {
                "attack_narrative": parsed.get("attack_narrative", "Analysis not available."),
                "risk_assessment": parsed.get("risk_assessment", "Unknown"),
                "next_steps": parsed.get("next_steps", "Review findings manually.")
            }
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response: {e}\nContent: {content[:200]}")
            return None

    def _simulate_analysis(self, crit_count: int, high_count: int, domain: str) -> Dict[str, str]:
        """Generate a convincing AI analysis based on finding counts (fallback)."""
        
        narrative = f"The automated reconnaissance of **{domain}** has completed. "
        
        if crit_count > 0:
            narrative += f"**CRITICAL ALERT**: The agent detected {crit_count} critical vulnerabilities that could lead to immediate compromise. "
            narrative += "The primary attack vector appears to be related to exposed sensitive resources or misconfigured access controls. "
            narrative += "An attacker could likely obtain shell access or sensitive data."
        elif high_count > 0:
            narrative += f"The agent identified {high_count} high-severity issues. "
            narrative += "While no immediate RCE was found, the combination of missing security headers and exposed surface area creates a significant risk of XSS or data leakage."
        else:
            narrative += "The target appears relatively hardened. No critical or high-severity vulnerabilities were immediately exploitable. "
            narrative += "However, the agent recommends reviewing the information disclosure findings to further reduce the attack surface."

        return {
            "attack_narrative": narrative,
            "risk_assessment": "Critical" if crit_count > 0 else "High" if high_count > 0 else "Medium",
            "next_steps": "1. Patch exposed Critical findings immediately.\n2. Review the generated PoC commands in the sandbox.\n3. Run a deeper manual audit on the discovered subdomains."
        }


def run_ai_analysis(findings: List[Dict[str, Any]], domain: str) -> Dict[str, str]:
    agent = AIPentestAgent()
    return agent.analyze(findings, domain)
