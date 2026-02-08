
import os
import random
from typing import Optional, Tuple

class KeyManager:
    """
    Manages API keys for different AI services.
    - 2 Keys for Pentest (Shannon) - Rotated (Gemini + Groq)
    - 1 Key for Consulting - Dedicated (Gemini)
    - 1 Key for Fallback - Emergency (Groq)
    
    Mapping from .env:
    - Consulting: GEMINI_API_KEY (Existing)
    - Pentest 1: GEMINI_KEY
    - Pentest 2: GROQ_KEY
    - Fallback: GROQ_API_KEY
    """
    
    _pentest_index = 0
    
    @classmethod
    def get_pentest_key(cls) -> Tuple[Optional[str], str]:
        """
        Returns (key, provider) for pentesting.
        Rotates between GEMINI_KEY and GROQ_KEY.
        """
        # Define pool: (EnvVar, Provider)
        pool = [
            ('GEMINI_KEY', 'gemini'),
            ('GROQ_KEY', 'groq')
        ]
        
        # Get actual values
        available_keys = []
        for env_var, provider in pool:
            val = os.getenv(env_var)
            if val:
                available_keys.append((val, provider))
        
        if not available_keys:
             return cls.get_fallback_key()

        # Rotate
        key_tuple = available_keys[cls._pentest_index % len(available_keys)]
        cls._pentest_index += 1
        return key_tuple

    @classmethod
    def get_consulting_key(cls) -> Optional[str]:
        """
        Returns the dedicated consulting key string (Gemini).
        Used by legacy AIService which expects just a string and assumes Gemini.
        """
        return os.getenv('GEMINI_API_KEY')

    @classmethod
    def get_fallback_key(cls) -> Tuple[Optional[str], str]:
        """Returns (key, provider) for fallback."""
        val = os.getenv('GROQ_API_KEY')
        if val:
            return (val, 'groq')
        return (None, 'unknown')
