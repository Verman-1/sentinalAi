"""
Adapter for models served locally via Ollama (https://ollama.com).

This talks to the standard Ollama chat endpoint. Point it at whatever
model you've pulled locally, e.g.:

    ollama pull llama3.1
    python -m sentinelai_harness.cli --adapter ollama --model llama3.1

No API key is needed since Ollama runs entirely on your own machine -
this is the primary, free, reproducible testbed the project synopsis
commits to (self-hosted models as the main experimental target).
"""

from .base import ModelAdapter, ChatMessage

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


class OllamaAdapter(ModelAdapter):
    def __init__(self, model_name: str = "llama3.1", base_url: str = "http://localhost:11434", timeout: int = 60):
        super().__init__(model_name)
        if requests is None:
            raise RuntimeError("The 'requests' package is required for OllamaAdapter. pip install requests")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _call(self, messages: list[ChatMessage]) -> str:
        payload = {
            "model": self.model_name,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": False,
        }
        try:
            resp = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=self.timeout)
            resp.raise_for_status()
        except requests.exceptions.ConnectionError as e:
            raise RuntimeError(
                f"Could not reach Ollama at {self.base_url}. Is `ollama serve` running "
                f"and have you pulled the '{self.model_name}' model?"
            ) from e
        data = resp.json()
        return data.get("message", {}).get("content", "")
