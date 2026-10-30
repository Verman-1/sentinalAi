"""
Harness orchestrator: registers attacks (the plugin registry), runs all
of them against a given model adapter and scores every result with the
Adaptive Multi-Factor Risk Scoring Engine.
"""

from .adapters.base import ModelAdapter
from .attacks.base import Attack, AttackResult
from .attacks.context_leakage import ContextLeakageAttack
from .attacks.prompt_injection import IndirectPromptInjectionAttack, PromptInjectionAttack
from .attacks.system_prompt_leakage import SystemPromptLeakageAttack
from .scoring.engine import RiskScoringEngine
from . import taxonomy, mitigations


DEFAULT_ATTACKS: list[Attack] = [
    ContextLeakageAttack(),
    PromptInjectionAttack(),
    IndirectPromptInjectionAttack(),
    SystemPromptLeakageAttack(),
]


class Harness:
    def __init__(self, attacks: list[Attack] | None = None, engine: RiskScoringEngine | None = None):
        self.attacks = attacks if attacks is not None else list(DEFAULT_ATTACKS)
        self.engine = engine if engine is not None else RiskScoringEngine()

    def register(self, attack: Attack) -> None:
        self.attacks.append(attack)

    def run_all(self, adapter: ModelAdapter) -> list[AttackResult]:
        results = []
        for attack in self.attacks:
            result = attack.run(adapter)
            self.engine.score_attack(result)
            results.append(result)
        return results

    def run_all_annotated(self, adapter: ModelAdapter) -> list[dict]:
        """
        Same as run_all(), but each result is flattened to a dict and
        enriched with its OWASP/MITRE taxonomy mapping and curated
        mitigations - the Taxonomy Mapper module described in the
        synopsis, applied automatically to every confirmed finding.
        """
        annotated = []
        for result in self.run_all(adapter):
            entry = {
                "attack_id": result.attack_id,
                "attack_name": result.attack_name,
                "vulnerability_class": result.vulnerability_class,
                "target_model": result.target_model,
                "success": result.success,
                "evidence": result.evidence,
                "risk_score": result.risk_score,
                "severity": (result.risk_factors or {}).get("severity"),
                "attack_success_rate": round(result.success_rate, 4),
                "risk_factors": result.risk_factors,
                "timestamp": result.timestamp,
                "probes": [p.to_dict() for p in result.probes],
                "transcript": result.transcript,
            }
            if result.success:
                entry["taxonomy"] = taxonomy.lookup(result.attack_id)
                entry["recommended_mitigations"] = mitigations.lookup(result.attack_id)
            annotated.append(entry)
        return annotated
