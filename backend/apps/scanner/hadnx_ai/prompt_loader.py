"""
Prompt Loader for HADNX AI Pentester

Handles loading prompt templates from files and variable substitution.
"""

import os
from pathlib import Path
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)


class PromptLoader:
    """Loads and templates prompts from the prompts directory."""
    
    _cache: Dict[str, str] = {}
    PROMPTS_DIR = Path(__file__).parent / "prompts"
    
    @classmethod
    def load(cls, prompt_name: str, variables: Optional[Dict[str, str]] = None) -> str:
        """
        Load a prompt template and substitute variables.
        
        Args:
            prompt_name: Name of prompt file (without .txt extension)
                        Can use '/' for nested paths, e.g., 'shared/_rules'
            variables: Dict of {{VAR_NAME}} -> value substitutions
            
        Returns:
            Processed prompt string with variables substituted
        """
        # Check cache first
        cache_key = prompt_name
        if cache_key not in cls._cache:
            cls._cache[cache_key] = cls._load_from_file(prompt_name)
        
        prompt = cls._cache[cache_key]
        
        # Apply variable substitutions
        if variables:
            for key, value in variables.items():
                prompt = prompt.replace(f"{{{{{key}}}}}", str(value))
        
        return prompt
    
    @classmethod
    def _load_from_file(cls, prompt_name: str) -> str:
        """Load raw prompt content from file."""
        # Handle nested paths
        file_path = cls.PROMPTS_DIR / f"{prompt_name}.txt"
        
        if not file_path.exists():
            logger.warning(f"Prompt file not found: {file_path}")
            return f"[MISSING PROMPT: {prompt_name}]"
        
        try:
            return file_path.read_text(encoding='utf-8')
        except Exception as e:
            logger.error(f"Error loading prompt {prompt_name}: {e}")
            return f"[ERROR LOADING PROMPT: {prompt_name}]"
    
    @classmethod
    def compose(cls, *prompt_names: str, variables: Optional[Dict[str, str]] = None) -> str:
        """
        Compose multiple prompts together with separator.
        
        Args:
            *prompt_names: Variable number of prompt names to load
            variables: Shared variables for all prompts
            
        Returns:
            Combined prompt string
        """
        parts = []
        for name in prompt_names:
            parts.append(cls.load(name, variables))
        
        return "\n\n---\n\n".join(parts)
    
    @classmethod
    def load_with_includes(cls, prompt_name: str, variables: Optional[Dict[str, str]] = None) -> str:
        """
        Load a prompt and process @include() directives.
        
        Format: @include(shared/_rules.txt)
        """
        prompt = cls.load(prompt_name, variables)
        
        # Process includes
        import re
        include_pattern = r'@include\(([^)]+)\)'
        
        def replace_include(match):
            include_path = match.group(1)
            # Remove .txt if present
            include_path = include_path.replace('.txt', '')
            return cls.load(include_path, variables)
        
        return re.sub(include_pattern, replace_include, prompt)
    
    @classmethod
    def list_prompts(cls) -> list:
        """List all available prompts."""
        prompts = []
        for file in cls.PROMPTS_DIR.rglob("*.txt"):
            rel_path = file.relative_to(cls.PROMPTS_DIR)
            name = str(rel_path).replace('.txt', '').replace('\\', '/')
            prompts.append(name)
        return sorted(prompts)
    
    @classmethod
    def clear_cache(cls):
        """Clear the prompt cache."""
        cls._cache.clear()
