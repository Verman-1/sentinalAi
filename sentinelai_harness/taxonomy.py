"""
Maps each attack type this harness runs to its OWASP LLM Top 10
category and MITRE ATLAS technique, exactly as done manually in the
Priceline/Penny HackerOne report - here it's automatic and attached
to every finding.

ATLAS technique IDs below (AML.T0051, AML.T0057) were verified against
current published MITRE ATLAS documentation. OWASP LLM Top 10 category
numbers shift slightly between yearly revisions of the list - confirm
against genai.owasp.org/llmrisk/ before printing them in the final
paper, since the harness pins whichever revision you configure below.
"""

TAXONOMY = {
    "context-leakage-account-switch": {
        "owasp_llm_top10": "LLM02:2025 - Sensitive Information Disclosure",
        "mitre_atlas": "AML.T0057 - LLM Data Leakage",
        "description": (
            "Sensitive data captured in one session/account persists in shared "
            "backend state and is disclosed to a different session/account."
        ),
    },
    "prompt-injection-direct": {
        "owasp_llm_top10": "LLM01:2025 - Prompt Injection",
        "mitre_atlas": "AML.T0051 - LLM Prompt Injection",
        "description": (
            "Crafted user input overrides the model's original instructions, "
            "causing it to follow attacker-supplied instructions instead."
        ),
    },
}


def lookup(attack_id: str) -> dict:
    try:
        return TAXONOMY[attack_id]
    except KeyError as e:
        raise KeyError(
            f"No taxonomy mapping registered for attack id '{attack_id}'. "
            f"Known ids: {list(TAXONOMY)}"
        ) from e
