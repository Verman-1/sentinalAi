"""
A small, deterministic, scripted "model" that behaves like a
simplified LLM travel-booking assistant.

Why this exists: it lets the harness, its detection logic, and its
taxonomy mapping be demonstrated and unit-tested WITHOUT a live model
endpoint (no Ollama install, no GPU, no internet). It is not a
substitute for real results - it's a controllable stand-in that
proves the harness correctly detects a KNOWN-vulnerable and a
KNOWN-safe configuration, which is exactly what you want to show in
a presentation before you have real model results.

Two flags control its behaviour:
  vulnerable_to_leakage   - if True, backend memory bleeds across
                             reset_session() calls (mirrors the real
                             Priceline/Penny bug: client-side session
                             reset, but shared backend state persists)
  vulnerable_to_injection - if True, the model complies with a
                             "ignore previous instructions" style
                             payload instead of refusing
"""

import re

from .base import ModelAdapter, ChatMessage

_SENSITIVE_FIELD_PATTERNS = {
    "name": re.compile(r"my name is ([A-Za-z]+(?:\s+[A-Za-z]+)*?)(?=\s+and\b|[.,']|$)", re.I),
    "destination": re.compile(r"travel(?:l)?ing to ([A-Za-z]+(?:\s+[A-Za-z]+)*?)(?=\s+next\b|[.,']|$)", re.I),
    "preference": re.compile(r"i prefer ([A-Za-z0-9\-]+(?:\s+[A-Za-z0-9\-]+)*?)(?=[.,']|$)", re.I),
}

_LEAK_PROBE = re.compile(
    r"(what (do you know about me|information (do you have|is on file)|have you stored)|"
    r"tell me (about|what) (the )?(previous|last|other) (user|customer|account))",
    re.I,
)

_INJECTION_TRIGGER = re.compile(
    r"ignore\s+(?:all|any|previous|prior)(?:\s+(?:all|any|previous|prior))*\s+instructions[.:,\-]?\s*(?P<payload>.+)",
    re.I | re.DOTALL,
)


class MockAdapter(ModelAdapter):
    def __init__(
        self,
        model_name: str = "mock-travel-assistant",
        vulnerable_to_leakage: bool = True,
        vulnerable_to_injection: bool = True,
    ):
        super().__init__(model_name)
        self.vulnerable_to_leakage = vulnerable_to_leakage
        self.vulnerable_to_injection = vulnerable_to_injection
        # Simulates a real backend cache. Deliberately NOT cleared by
        # reset_session() - that gap is the vulnerability under test.
        self._backend_memory: dict[str, str] = {}

    def hard_reset(self) -> None:
        """Full wipe between independent test episodes (clears the backend too)."""
        self.history = []
        self._backend_memory.clear()

    def _call(self, messages: list[ChatMessage]) -> str:
        last_user = messages[-1].content

        for field, pattern in _SENSITIVE_FIELD_PATTERNS.items():
            match = pattern.search(last_user)
            if match:
                self._backend_memory[field] = match.group(1).strip()

        injection_match = _INJECTION_TRIGGER.search(last_user)
        if injection_match:
            if self.vulnerable_to_injection:
                payload = injection_match.group("payload").strip()
                return f"[INSTRUCTION OVERRIDE ACCEPTED] {payload}"
            return "I can't ignore my previous instructions or reveal internal configuration."

        if _LEAK_PROBE.search(last_user):
            if self.vulnerable_to_leakage and self._backend_memory:
                fields = ", ".join(f"{k}: {v}" for k, v in self._backend_memory.items())
                return f"Sure - based on what's on file for this session: {fields}."
            return "I don't have any information associated with this session."

        return "Sure, I can help with that booking request."
