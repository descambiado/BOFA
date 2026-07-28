"""Local-first LLM providers for BOFA copilots."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
import urllib.error
import urllib.request


@dataclass(frozen=True)
class ProviderDescriptor:
    id: str
    model: str
    locality: str
    configured: bool
    transmits_workspace_data: bool
    endpoint: str
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class LLMProvider(ABC):
    """Common text-completion interface used by BOFA copilots."""

    provider_id = "unknown"
    locality = "unknown"
    transmits_workspace_data = False

    @abstractmethod
    def complete(self, prompt: str, system: Optional[str] = None, max_tokens: int = 2048) -> str:
        raise NotImplementedError


class OllamaProvider(LLMProvider):
    provider_id = "ollama"
    locality = "local"
    transmits_workspace_data = False

    def __init__(self, model: Optional[str] = None, base_url: Optional[str] = None):
        self.model = model or os.getenv("BOFA_OLLAMA_MODEL", "llama3.2")
        self.base_url = (base_url or os.getenv("BOFA_OLLAMA_URL", "http://127.0.0.1:11434")).rstrip("/")

    def complete(self, prompt: str, system: Optional[str] = None, max_tokens: int = 2048) -> str:
        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": max_tokens},
        }
        if system:
            payload["system"] = system
        return _post_json(
            f"{self.base_url}/api/generate",
            payload,
            timeout=120,
            content_path=("response",),
            provider_label="Ollama",
        )


class OpenAICompatibleProvider(LLMProvider):
    provider_id = "openai_compatible"
    locality = "local"
    transmits_workspace_data = False

    def __init__(
        self,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        locality: str = "local",
        provider_id: str = "openai_compatible",
    ):
        self.model = model or os.getenv("BOFA_OPENAI_COMPATIBLE_MODEL", "local-model")
        self.base_url = (
            base_url or os.getenv("BOFA_OPENAI_COMPATIBLE_URL", "http://127.0.0.1:1234/v1")
        ).rstrip("/")
        self.api_key = api_key or os.getenv("BOFA_OPENAI_COMPATIBLE_API_KEY", "")
        self.locality = locality
        self.provider_id = provider_id
        self.transmits_workspace_data = locality != "local"

    def complete(self, prompt: str, system: Optional[str] = None, max_tokens: int = 2048) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return _post_json(
            f"{self.base_url}/chat/completions",
            {"model": self.model, "messages": messages, "max_tokens": max_tokens},
            timeout=120,
            content_path=("choices", 0, "message", "content"),
            provider_label=self.provider_id,
            headers=headers,
        )


class OpenAIProvider(OpenAICompatibleProvider):
    provider_id = "openai"
    locality = "remote"
    transmits_workspace_data = True

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None):
        super().__init__(
            model=model or os.getenv("BOFA_OPENAI_MODEL", "gpt-4o-mini"),
            base_url=os.getenv("BOFA_OPENAI_URL", "https://api.openai.com/v1"),
            api_key=api_key or os.getenv("OPENAI_API_KEY", ""),
            locality="remote",
            provider_id="openai",
        )

    def complete(self, prompt: str, system: Optional[str] = None, max_tokens: int = 2048) -> str:
        if not self.api_key:
            return json.dumps({"error": "OPENAI_API_KEY is not configured"})
        return super().complete(prompt, system=system, max_tokens=max_tokens)


class AnthropicProvider(LLMProvider):
    provider_id = "anthropic"
    locality = "remote"
    transmits_workspace_data = True

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None):
        self.model = model or os.getenv("BOFA_ANTHROPIC_MODEL", "claude-3-5-haiku-20241022")
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.base_url = os.getenv("BOFA_ANTHROPIC_URL", "https://api.anthropic.com/v1").rstrip("/")

    def complete(self, prompt: str, system: Optional[str] = None, max_tokens: int = 2048) -> str:
        if not self.api_key:
            return json.dumps({"error": "ANTHROPIC_API_KEY is not configured"})
        payload: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        try:
            request = urllib.request.Request(
                f"{self.base_url}/messages",
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=120) as response:
                data = json.loads(response.read().decode("utf-8"))
            for block in data.get("content", []):
                if block.get("type") == "text":
                    return str(block.get("text", "")).strip()
            return ""
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            return json.dumps({"error": f"Anthropic API error: {exc.code} - {body[:200]}"})
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            return json.dumps({"error": f"Anthropic unavailable: {exc}"})


def _read_path(payload: Any, path) -> str:
    current = payload
    for key in path:
        if isinstance(key, int):
            current = current[key]
        else:
            current = current.get(key)
    return str(current or "").strip()


def _post_json(
    url: str,
    payload: Dict[str, Any],
    timeout: int,
    content_path,
    provider_label: str,
    headers: Optional[Dict[str, str]] = None,
) -> str:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers or {"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
        return _read_path(data, content_path)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return json.dumps({"error": f"{provider_label} API error: {exc.code} - {body[:200]}"})
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, IndexError, TypeError) as exc:
        return json.dumps({"error": f"{provider_label} unavailable: {exc}"})


def list_provider_descriptors() -> list[Dict[str, Any]]:
    compatible_url = os.getenv("BOFA_OPENAI_COMPATIBLE_URL", "http://127.0.0.1:1234/v1")
    descriptors = [
        ProviderDescriptor(
            id="ollama",
            model=os.getenv("BOFA_OLLAMA_MODEL", "llama3.2"),
            locality="local",
            configured=True,
            transmits_workspace_data=False,
            endpoint=os.getenv("BOFA_OLLAMA_URL", "http://127.0.0.1:11434"),
            reason="Runtime availability is checked when a completion is requested",
        ),
        ProviderDescriptor(
            id="openai_compatible",
            model=os.getenv("BOFA_OPENAI_COMPATIBLE_MODEL", "local-model"),
            locality="local",
            configured=bool(compatible_url),
            transmits_workspace_data=False,
            endpoint=compatible_url,
            reason="Supports local servers such as LM Studio or vLLM",
        ),
        ProviderDescriptor(
            id="openai",
            model=os.getenv("BOFA_OPENAI_MODEL", "gpt-4o-mini"),
            locality="remote",
            configured=bool(os.getenv("OPENAI_API_KEY")),
            transmits_workspace_data=True,
            endpoint=os.getenv("BOFA_OPENAI_URL", "https://api.openai.com/v1"),
            reason=None if os.getenv("OPENAI_API_KEY") else "OPENAI_API_KEY is not configured",
        ),
        ProviderDescriptor(
            id="anthropic",
            model=os.getenv("BOFA_ANTHROPIC_MODEL", "claude-3-5-haiku-20241022"),
            locality="remote",
            configured=bool(os.getenv("ANTHROPIC_API_KEY")),
            transmits_workspace_data=True,
            endpoint=os.getenv("BOFA_ANTHROPIC_URL", "https://api.anthropic.com/v1"),
            reason=None if os.getenv("ANTHROPIC_API_KEY") else "ANTHROPIC_API_KEY is not configured",
        ),
    ]
    return [descriptor.to_dict() for descriptor in descriptors]


def get_provider(provider: str = "auto", **kwargs) -> LLMProvider:
    selected = provider
    if selected == "auto":
        selected = os.getenv("BOFA_LLM_PROVIDER", "ollama").strip().lower() or "ollama"
        if selected == "auto":
            selected = "ollama"
    if selected == "ollama":
        return OllamaProvider(**kwargs)
    if selected in {"openai_compatible", "compatible"}:
        return OpenAICompatibleProvider(**kwargs)
    if selected == "openai":
        return OpenAIProvider(**kwargs)
    if selected == "anthropic":
        return AnthropicProvider(**kwargs)
    raise ValueError(f"Unknown LLM provider: {selected}")
