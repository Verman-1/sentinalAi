"""
Base interface every target-model adapter must implement.

The harness never talks to a model directly - it only talks to a
ModelAdapter. This is what lets the same attack code run against
Ollama, HuggingFace, the offline ScriptedLLM, or a full LLM application
(targets.travel_app.TravelAssistApp) interchangeably, and is the
extension point for adding new providers later (matches the
provider-adapter pattern already used in the LLM Red Team Lab).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass


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

    def complete(self, messages: list[ChatMessage]) -> str:
        """
        One stateless completion over an explicit message list - no
        history bookkeeping. Used by application-level targets (which
        build their own prompts) and by the LLM-as-judge.
        """
        return self._call(messages)

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

    def switch_account(self, account_id: str) -> None:
        """
        Simulate logging out and logging in as `account_id` on the same
        device/browser. A bare model has no notion of accounts, so the
        default is just a client-side session reset; targets with an
        account/memory layer (TravelAssistApp) override this.
        """
        self.reset_session()

    def hard_reset(self) -> None:
        """
        Wipe ALL state, including any simulated backend memory, so that
        independent test episodes cannot contaminate each other.
        """
        self.reset_session()
