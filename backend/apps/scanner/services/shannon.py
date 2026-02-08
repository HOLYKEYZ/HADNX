
import logging
import google.generativeai as genai
import requests
import json
from .key_manager import KeyManager

logger = logging.getLogger(__name__)

class AIAdapter:
    """
    Unified interface for Gemini and Groq.
    """
    def __init__(self, key, provider):
        self.key = key
        self.provider = provider
        self.gemini_model = None

    def generate_content(self, prompt):
        if self.provider == 'gemini':
            return self._generate_gemini(prompt)
        elif self.provider == 'groq':
            return self._generate_groq(prompt)
        else:
             raise ValueError("Unknown provider")

    def _generate_gemini(self, prompt):
        genai.configure(api_key=self.key)
        model = genai.GenerativeModel('gemini-2.5-flash')
        try:
             response = model.generate_content(prompt)
             return type('obj', (object,), {'text': response.text})
        except Exception as e:
             # Fallback to 1.5 if 2.5 fails
             model = genai.GenerativeModel('gemini-1.5-flash')
             response = model.generate_content(prompt)
             return type('obj', (object,), {'text': response.text})

    def _generate_groq(self, prompt):
        # Groq API (OpenAI compatible)
        try:
            resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "llama-3.3-70b-versatile",
                    "messages": [
                        {"role": "system", "content": "You are Shannon, an autonomous pentester."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.3
                },
                timeout=30
            )
            resp.raise_for_status()
            content = resp.json()['choices'][0]['message']['content']
            return type('obj', (object,), {'text': content})
        except Exception as e:
            raise Exception(f"Groq API Error: {e}")

class ShannonAgent:
    """
    Shannon: Autonomous AI Pentester.
    Capabilities:
    - Reconnaissance
    - Vulnerability Analysis
    - Exploit Generation (PoC)
    """

    def __init__(self):
        pass

    def _get_model(self):
        """Initializes the AI model with a rotated key/provider."""
        key, provider = KeyManager.get_pentest_key()
        
        if not key:
            # Try fallback
            key, provider = KeyManager.get_fallback_key()
            
        if not key:
            logger.error("No Pentest or Fallback keys available for Shannon.")
            return None
        
        try:
            return AIAdapter(key, provider)
        except Exception as e:
            logger.error(f"Failed to configure Shannon with {provider}: {e}")
            return None

    def audit_target(self, target_url: str, scan_context: dict = None):
        """
        Main entry point for Shannon to audit a target.
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
            # Clean up markdown code blocks if Groq adds them
            text = response.text
            if text.startswith("```json"): text = text[7:]
            if text.endswith("```"): text = text[:-3]
            return text
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
