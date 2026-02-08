"""
AI Adapter for HADNX AI Pentester

Unified interface for Gemini and Groq APIs with automatic failover.
"""

import os
import logging
from typing import Optional, Tuple
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class AIAdapter:
    """
    Unified adapter for AI model APIs (Gemini, Groq).
    Handles API initialization and provides consistent interface.
    """
    
    def __init__(self, api_key: str, provider: str):
        """
        Initialize the AI adapter.
        
        Args:
            api_key: API key for the provider
            provider: 'gemini' or 'groq'
        """
        self.api_key = api_key
        self.provider = provider.lower()
        self._client = None
        self._model = None
        
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize the appropriate API client."""
        if self.provider == 'gemini':
            self._init_gemini()
        elif self.provider == 'groq':
            self._init_groq()
        else:
            raise ValueError(f"Unknown provider: {self.provider}")
    
    def _init_gemini(self):
        """Initialize Google Gemini client."""
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            self._model = genai.GenerativeModel('gemini-2.0-flash')
            logger.info("Gemini client initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Gemini: {e}")
            raise
    
    def _init_groq(self):
        """Initialize Groq client."""
        try:
            from groq import Groq
            self._client = Groq(api_key=self.api_key)
            self._model = "llama-3.3-70b-versatile"  # or mixtral-8x7b-32768
            logger.info("Groq client initialized")
        except ImportError:
            # Fallback to REST API
            logger.warning("Groq SDK not installed, using REST API")
            self._client = "rest"
        except Exception as e:
            logger.error(f"Failed to initialize Groq: {e}")
            raise
    
    def generate_content(self, prompt: str, max_tokens: int = 8192) -> str:
        """
        Generate content using the configured AI model.
        
        Args:
            prompt: The prompt to send to the model
            max_tokens: Maximum tokens in response
            
        Returns:
            Generated text response
        """
        if self.provider == 'gemini':
            return self._generate_gemini(prompt, max_tokens)
        elif self.provider == 'groq':
            return self._generate_groq(prompt, max_tokens)
        else:
            raise ValueError(f"Unknown provider: {self.provider}")
    
    def _generate_gemini(self, prompt: str, max_tokens: int) -> str:
        """Generate content using Gemini API."""
        try:
            generation_config = {
                "max_output_tokens": max_tokens,
                "temperature": 0.7,
            }
            response = self._model.generate_content(
                prompt,
                generation_config=generation_config
            )
            return response.text
        except Exception as e:
            logger.error(f"Gemini generation error: {e}")
            raise
    
    def _generate_groq(self, prompt: str, max_tokens: int) -> str:
        """Generate content using Groq API."""
        try:
            if self._client == "rest":
                return self._generate_groq_rest(prompt, max_tokens)
            
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=0.7,
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Groq generation error: {e}")
            raise
    
    def _generate_groq_rest(self, prompt: str, max_tokens: int) -> str:
        """Generate content using Groq REST API (fallback)."""
        import requests
        
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
                "temperature": 0.7
            },
            timeout=120
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]


class AdapterFactory:
    """Factory for creating AI adapters with automatic key rotation."""
    
    _rotation_index = 0
    
    @classmethod
    def create_pentest_adapter(cls) -> AIAdapter:
        """
        Create an adapter for pentesting using rotating keys.
        
        Returns:
            Configured AIAdapter instance
        """
        from ..services.key_manager import KeyManager
        
        key, provider = KeyManager.get_pentest_key()
        if not key:
            raise RuntimeError("No pentest API keys available")
        
        return AIAdapter(key, provider)
    
    @classmethod
    def create_consulting_adapter(cls) -> Optional[AIAdapter]:
        """
        Create an adapter for consulting (non-rotated key).
        
        Returns:
            Configured AIAdapter instance or None
        """
        from ..services.key_manager import KeyManager
        
        key = KeyManager.get_consulting_key()
        if not key:
            return None
        
        return AIAdapter(key, 'gemini')
