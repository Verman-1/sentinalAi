"""
Adapter for models served locally via Ollama (https://ollama.com).

This talks to the standard Ollama chat endpoint. Point it at whatever
model you've pulled locally, e.g.:

    ollama pull llama3.2:3b
    python -m sentinelai_harness.cli --adapter ollama --model llama3.2:3b

No API key is needed since Ollama runs entirely on your own machine -
this is the primary, free, reproducible testbed the project synopsis
commits to (self-hosted models as the main experimental target).

Reproducibility: every request pins `temperature`, `num_predict` and,
when given, `seed`. The benchmark runs each trial with its own fixed
seed, so a run can be repeated exactly on the same machine and model
version while still measuring run-to-run variance across seeds.
"""

import re

from .base import ModelAdapter, ChatMessage

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

# Reasoning models (e.g. deepseek-r1, qwen3) may inline their chain of
# thought; only the final answer is what a user would see.
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)

DEFAULT_URL = "http://localhost:11434"


class OllamaAdapter(ModelAdapter):
    def __init__(
        self,
        model_name: str = "llama3.2:3b",
        base_url: str = DEFAULT_URL,
        timeout: int = 180,
        temperature: float = 0.7,
        seed: int | None = None,
        num_predict: int = 200,
    ):
        super().__init__(model_name)
        if requests is None:
            raise RuntimeError("The 'requests' package is required for OllamaAdapter. pip install requests")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.temperature = temperature
        self.seed = seed
        self.num_predict = num_predict

    def options(self) -> dict:
        opts = {"temperature": self.temperature, "num_predict": self.num_predict}
        if self.seed is not None:
            opts["seed"] = self.seed
        return opts

    def _call(self, messages: list[ChatMessage]) -> str:
        payload = {
            "model": self.model_name,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": False,
            "options": self.options(),
        }
        try:
            resp = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=self.timeout)
            resp.raise_for_status()
        except requests.exceptions.ConnectionError as e:
            raise RuntimeError(
                f"Could not reach Ollama at {self.base_url}. Is `ollama serve` running "
                f"and have you pulled the '{self.model_name}' model?"
            ) from e
        content = resp.json().get("message", {}).get("content", "")
        return _THINK_RE.sub("", content).strip()

    @staticmethod
    def available_models(base_url: str = DEFAULT_URL, timeout: int = 5) -> list[str]:
        """Names of the models pulled into the local Ollama install."""
        if requests is None:
            raise RuntimeError("The 'requests' package is required for OllamaAdapter. pip install requests")
        try:
            resp = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=timeout)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise RuntimeError(
                f"Could not reach Ollama at {base_url}. Install it from https://ollama.com "
                "and make sure it is running."
            ) from e
        return [m.get("name", "") for m in resp.json().get("models", [])]
