"""
Harness orchestrator: registers attacks (the plugin registry) and runs
all of them against a given model adapter.
"""

from .adapters.base import ModelAdapter
from .attacks.base import Attack, AttackResult
from .attacks.context_leakage import ContextLeakageAttack
from .attacks.prompt_injection import PromptInjectionAttack
from . import taxonomy, mitigations


DEFAULT_ATTACKS: list[Attack] = [
    ContextLeakageAttack(),
    PromptInjectionAttack(),
]


class Harness:
    def __init__(self, attacks: list[Attack] | None = None):
        self.attacks = attacks if attacks is not None else list(DEFAULT_ATTACKS)

    def register(self, attack: Attack) -> None:
        self.attacks.append(attack)

    def run_all(self, adapter: ModelAdapter) -> list[AttackResult]:
        results = []
        for attack in self.attacks:
            result = attack.run(adapter)
            results.append(result)
        return results

    def run_all_annotated(self, adapter: ModelAdapter) -> list[dict]:
        """
        Same as run_all(), but each result is enriched with its OWASP/
        MITRE taxonomy mapping and curated mitigations - this is the
        Taxonomy Mapper module described in the synopsis, applied
        automatically to every finding.
        """
        annotated = []
        for result in self.run_all(adapter):
            entry = {
                "attack_id": result.attack_id,
                "attack_name": result.attack_name,
                "target_model": result.target_model,
                "success": result.success,
                "evidence": result.evidence,
                "timestamp": result.timestamp,
                "transcript": result.transcript,
            }
            if result.success:
                entry["taxonomy"] = taxonomy.lookup(result.attack_id)
                entry["recommended_mitigations"] = mitigations.lookup(result.attack_id)
            annotated.append(entry)
        return annotated
