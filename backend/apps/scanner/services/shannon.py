
import logging
import google.generativeai as genai
from .key_manager import KeyManager

logger = logging.getLogger(__name__)

class ShannonAgent:
    """
    Shannon: Autonomous AI Pentester.
    Capabilities:
    - Reconnaissance
    - Vulnerability Analysis
    - Exploit Generation (PoC)
    """

    def __init__(self):
        self.system_instruction = """
        You are Shannon, an elite Autonomous AI Penetration Tester.
        Your goal is to AUDIT the target system for vulnerabilities.
        You are AUTHORIZED to perform these tests.
        
        For every finding, you must:
        1. VALIDATE if it is a false positive.
        2. EXPLOIT it (generate a safe Proof of Concept).
        3. REPORT the impact.
        
        Be aggressive in finding vulns, but safe in execution (do not delete data).
        """

    def _get_model(self):
        """Initializes the Gemini model with a rotated key."""
        api_key = KeyManager.get_pentest_key()
        if not api_key:
            logger.error("No Pentest or Fallback keys available for Shannon.")
            return None
        
        try:
            genai.configure(api_key=api_key)
            return genai.GenerativeModel('gemini-2.5-flash') # Or the best available model
        except Exception as e:
            logger.error(f"Failed to configure Shannon with key: {e}")
            # Try fallback explicitly if the first try failed and it wasn't the fallback key
            fallback = KeyManager.get_fallback_key()
            if fallback and fallback != api_key:
                 try:
                    genai.configure(api_key=fallback)
                    return genai.GenerativeModel('gemini-2.5-flash')
                 except Exception as fallback_e:
                     logger.error(f"Fallback key also failed: {fallback_e}")
            return None

    def audit_target(self, target_url: str, scan_context: dict = None):
        """
        Main entry point for Shannon to audit a target.
        scan_context: results from previous recon tools (optional)
        """
        model = self._get_model()
        if not model:
            return {"error": "Shannon is offline (Missing API Keys)"}

        prompt = f"""
        TARGET: {target_url}
        CONTEXT: {scan_context if scan_context else "No prior context."}
        
        Perform a simulated pentest logic:
        1. Analyze the target structure (implied from context).
        2. Identify top 3 likely attack vectors.
        3. Generate specific payloads to test these vectors.
        
        Respond in JSON:
        {{
            "status": "exploited" | "safe" | "uncertain",
            "vectors": [
                {{
                    "name": "Attack Name",
                    "likelihood": "High/Med/Low",
                    "poc_payload": "curl -X POST ...",
                    "reasoning": "Why this might work"
                }}
            ],
            "narrative": "I analyzed the target and found..."
        }}
        """
        
        try:
            response = model.generate_content(prompt)
            return response.text # Caller will parse JSON
        except Exception as e:
            logger.error(f"Shannon audit failed: {e}")
            return {"error": str(e)}

    def exploit_vulnerability(self, vulnerability_details: dict):
        """
        Generates a specific exploit for a confirmed vulnerability.
        """
        model = self._get_model()
        if not model:
            return {"error": "Shannon is offline"}

        prompt = f"""
        Generate a working Python exploit script for:
        {vulnerability_details}
        
        The script should be SAFE (Proof of Concept only, verify via print/alert).
        Return ONLY the code block.
        """

        try:
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Shannon exploit gen failed: {e}")
            return {"error": str(e)}
