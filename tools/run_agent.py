#!/usr/bin/env python3
"""
Run Security Copilot - BOFA plan-first assistant
=================================================

Plans an evidence-rich next step. Execution is disabled unless an explicit
authorization grant and execution profile pass BOFA policy.

LLM local (Ollama):
    ollama pull llama3.2
    ollama serve
    python3 tools/run_agent.py https://yungkuoo.com --provider ollama

LLM por API (OpenAI/Anthropic):
    export OPENAI_API_KEY=sk-...
    python3 tools/run_agent.py https://yungkuoo.com --provider openai

    export ANTHROPIC_API_KEY=sk-ant-...
    python3 tools/run_agent.py https://yungkuoo.com --provider anthropic
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from agents.security_agent import main

if __name__ == "__main__":
    sys.exit(main())
