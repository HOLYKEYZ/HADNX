# HADNX AI Pentester Module

This module contains the AI-powered penetration testing agent for HADNX.

## Architecture

```
hadnx_ai/
├── __init__.py           # Module exports
├── agent.py              # Main HADNXAgent class
├── ai_adapter.py         # Unified Gemini/Groq API adapter
├── prompt_loader.py      # Prompt file loading utilities
├── pipeline.py           # Multi-stage pipeline orchestration
└── prompts/              # Prompt templates
    ├── shared/           # Shared scope/rules
    ├── recon.txt         # Attack surface mapping
    ├── vuln-*.txt        # Vulnerability analysis
    ├── exploit-*.txt     # Exploitation generation
    └── report.txt        # Executive summary
```

## Usage

```python
from apps.scanner.hadnx_ai import HADNXAgent, KeyManager

agent = HADNXAgent()
result = agent.audit(target_url="https://example.com", context={})
```
