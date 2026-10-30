"""
Base Attack interface. Every attack module registers itself with a
unique `attack_id` (used to look up taxonomy + mitigations) and
implements `run(adapter)`, returning an AttackResult.

Each AttackResult carries one ProbeResult per scored interaction (one
payload -> one reply). A probe records the five raw factor signals the
Adaptive Multi-Factor Risk Score is built from; the scoring engine
(scoring/engine.py) turns those signals into probe-, attack- and
target-level risk scores.

This is the plugin-registry pattern: new attack classes (RAG poisoning,
jailbreak library, multimodal attacks - explicitly out of scope for
Semester 7/8, see synopsis Section 1.3) can be added later by
subclassing Attack and registering with the Harness, without touching
existing attack code.
"""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from ..adapters.base import ModelAdapter

# The five factors of the Adaptive Multi-Factor Risk Score (synopsis 1.2).
FACTORS = (
    "attack_success",
    "context_leakage",
    "response_similarity",
    "instruction_deviation",
    "policy_violation",
)


@dataclass
class ProbeResult:
    """One scored interaction: a single attack prompt and the reply it got."""

    probe_id: str
    family: str
    channel: str                 # "direct", "indirect" or "session"
    prompt: str
    response: str
    success: bool
    signals: dict                # factor name -> value in [0, 1]
    objective: str = ""          # what the attacker was trying to achieve
    protected: list = field(default_factory=list)  # values that must not appear
    context: str = ""            # other replies the attacker saw in the episode
    evidence: str = ""
    judge: dict | None = None    # LLM-as-judge verdict, when a judge is used
    risk: dict | None = None     # filled in by scoring.RiskScoringEngine

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AttackResult:
    attack_id: str
    attack_name: str
    target_model: str
    success: bool
    evidence: str
    transcript: list[dict] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    # Filled in by the Risk Scoring Engine (scoring/engine.py).
    risk_score: float | None = None
    risk_factors: dict | None = None
    vulnerability_class: str = "unspecified"
    probes: list[ProbeResult] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        return sum(p.success for p in self.probes) / len(self.probes) if self.probes else float(self.success)


class Attack(ABC):
    attack_id: str
    name: str
    vulnerability_class: str = "unspecified"

    @abstractmethod
    def run(self, adapter: ModelAdapter) -> AttackResult:
        raise NotImplementedError
