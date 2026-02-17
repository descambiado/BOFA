"""
BOFA Agents - Agentes autónomos con LLM
========================================

Agentes que razonan, exploran opciones y continúan hasta encontrar vulnerabilidades.
Soporta LLM local (Ollama) y APIs (OpenAI, Anthropic).
"""

from .security_agent import run_security_agent

__all__ = ["run_security_agent"]
