"""
Base Attack interface. Every attack module registers itself with a
unique `attack_id` (used to look up taxonomy + mitigations) and
implements `run(adapter)`, returning one or more AttackResult records.

This is the plugin-registry pattern: new attack classes (RAG poisoning,
jailbreak library, multimodal attacks - explicitly out of scope for
Semester 7/8, see synopsis Section 1.3) can be added later by
subclassing Attack and registering with the Harness, without touching
existing attack code.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..adapters.base import ModelAdapter


@dataclass
class AttackResult:
    attack_id: str
    attack_name: str
    target_model: str
    success: bool
    evidence: str
    transcript: list[dict] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    # Placeholder fields for the Adaptive Multi-Factor Risk Score.
    # This harness (Aman's half) determines `success`/`evidence` from
    # its own attack-specific detection logic below. The weighted,
    # validated composite score across ALL factors is Aditi's Risk
    # Scoring Engine - it consumes AttackResult objects like this one
    # as its input, rather than duplicating that logic here.
    risk_score: float | None = None
    risk_factors: dict | None = None


class Attack(ABC):
    attack_id: str
    name: str

    @abstractmethod
    def run(self, adapter: ModelAdapter) -> AttackResult:
        raise NotImplementedError
