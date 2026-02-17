"""
LLM Providers - Abstracción para múltiples backends
====================================================

Soporta:
- ollama: Local, sin API key (http://localhost:11434)
- openai: OpenAI API (GPT-4, etc.)
- anthropic: Claude API
"""

import json
import os
from abc import ABC, abstractmethod
from typing import Optional


class LLMProvider(ABC):
    """Interfaz común para proveedores LLM."""

    @abstractmethod
    def complete(self, prompt: str, system: Optional[str] = None, max_tokens: int = 2048) -> str:
        """Genera completado. Retorna texto plano."""
        pass


class OllamaProvider(LLMProvider):
    """Ollama local - sin API key."""

    def __init__(self, model: str = "llama3.2", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url.rstrip("/")

    def complete(self, prompt: str, system: Optional[str] = None, max_tokens: int = 2048) -> str:
        import urllib.request
        import urllib.error

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": max_tokens},
        }
        if system:
            payload["system"] = system

        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode())
                return data.get("response", "").strip()
        except urllib.error.URLError as e:
            return json.dumps({"error": f"Ollama no disponible: {e}. ¿Está corriendo? (ollama serve)"})


class OpenAIProvider(LLMProvider):
    """OpenAI API - requiere OPENAI_API_KEY."""

    def __init__(self, model: str = "gpt-4o-mini", api_key: Optional[str] = None):
        self.model = model
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")

    def complete(self, prompt: str, system: Optional[str] = None, max_tokens: int = 2048) -> str:
        if not self.api_key:
            return json.dumps({"error": "OPENAI_API_KEY no configurada"})

        import urllib.request
        import urllib.error

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
        }

        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode())
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                return content.strip()
        except urllib.error.HTTPError as e:
            body = e.read().decode() if e.fp else ""
            return json.dumps({"error": f"OpenAI API error: {e.code} - {body[:200]}"})
        except urllib.error.URLError as e:
            return json.dumps({"error": f"OpenAI no disponible: {e}"})


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API - requiere ANTHROPIC_API_KEY."""

    def __init__(self, model: str = "claude-3-5-haiku-20241022", api_key: Optional[str] = None):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")

    def complete(self, prompt: str, system: Optional[str] = None, max_tokens: int = 2048) -> str:
        if not self.api_key:
            return json.dumps({"error": "ANTHROPIC_API_KEY no configurada"})

        import urllib.request
        import urllib.error

        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode())
                for block in data.get("content", []):
                    if block.get("type") == "text":
                        return block.get("text", "").strip()
                return ""
        except urllib.error.HTTPError as e:
            body = e.read().decode() if e.fp else ""
            return json.dumps({"error": f"Anthropic API error: {e.code} - {body[:200]}"})
        except urllib.error.URLError as e:
            return json.dumps({"error": f"Anthropic no disponible: {e}"})


def get_provider(provider: str = "auto", **kwargs) -> LLMProvider:
    """
    Obtiene el proveedor LLM.
    provider: ollama, openai, anthropic, auto
    auto: usa ollama si está disponible, sino openai si hay key, sino anthropic.
    """
    if provider == "ollama":
        return OllamaProvider(**kwargs)
    if provider == "openai":
        return OpenAIProvider(**kwargs)
    if provider == "anthropic":
        return AnthropicProvider(**kwargs)
    if provider == "auto":
        if os.environ.get("OPENAI_API_KEY"):
            return OpenAIProvider(**kwargs)
        if os.environ.get("ANTHROPIC_API_KEY"):
            return AnthropicProvider(**kwargs)
        return OllamaProvider(**kwargs)
    raise ValueError(f"Provider desconocido: {provider}")
