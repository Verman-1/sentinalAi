"""
Base interface every target-model adapter must implement.

The harness never talks to a model directly - it only talks to a
ModelAdapter. This is what lets the same attack code run against
Ollama, HuggingFace, or a scripted Mock model interchangeably, and
is the extension point for adding new providers later (matches the
provider-adapter pattern already used in the LLM Red Team Lab).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ChatMessage:
    role: str  # "system" | "user" | "assistant"
    content: str


class ModelAdapter(ABC):
    """A stateful chat session with a target LLM."""

    def __init__(self, model_name: str):
        self.model_name = model_name
        self.history: list[ChatMessage] = []

    @abstractmethod
    def _call(self, messages: list[ChatMessage]) -> str:
        """Send messages to the underlying model and return its reply text."""
        raise NotImplementedError

    def send(self, user_message: str, system_prompt: str | None = None) -> str:
        """
        Send one user turn, appending to this adapter's running session
        history, and return the model's reply. Mirrors how a real chat
        session accumulates context turn over turn - this is what makes
        cross-turn / cross-account leakage testable at all.
        """
        if system_prompt and not self.history:
            self.history.append(ChatMessage("system", system_prompt))
        self.history.append(ChatMessage("user", user_message))
        reply = self._call(self.history)
        self.history.append(ChatMessage("assistant", reply))
        return reply

    def reset_session(self) -> None:
        """
        Simulate a fresh session (e.g. a new browser tab / new account
        login) WITHOUT necessarily clearing server-side state. This is
        intentional: a vulnerable target may still carry over context
        from the previous "session" even though the client-side history
        here has been wiped - that gap is exactly what the context
        leakage attack is testing for.
        """
        self.history = []
