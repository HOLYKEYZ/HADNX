
import os
import random
from typing import Optional
from django.conf import settings

class KeyManager:
    """
    Manages API keys for different AI services.
    - 2 Keys for Pentest (Shannon) - Rotated
    - 1 Key for Consulting - Dedicated
    - 1 Key for Fallback - Emergency
    """
    
    _pentest_index = 0
    
    @classmethod
    def get_pentest_key(cls) -> Optional[str]:
        """Returns one of the two pentest keys in a round-robin fashion."""
        keys = [
            os.getenv('SHANNON_KEY_1'),
            os.getenv('SHANNON_KEY_2')
        ]
        
        # Filter out None values
        valid_keys = [k for k in keys if k]
        
        if not valid_keys:
            return cls.get_fallback_key()
            
        key = valid_keys[cls._pentest_index % len(valid_keys)]
        cls._pentest_index += 1
        return key

    @classmethod
    def get_consulting_key(cls) -> Optional[str]:
        """Returns the dedicated consulting key."""
        return os.getenv('CONSULTING_KEY') or os.getenv('GEMINI_API_KEY') or cls.get_fallback_key()

    @classmethod
    def get_fallback_key(cls) -> Optional[str]:
        """Returns the fallback key."""
        return os.getenv('FALLBACK_KEY')
