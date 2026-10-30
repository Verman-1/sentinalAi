"""
Maps each attack type this harness runs to its OWASP LLM Top 10
category and MITRE ATLAS technique, exactly as done manually in the
Priceline/Penny HackerOne report - here it's automatic and attached
to every finding.

MITRE ATLAS IDs and names were checked against MITRE's official
atlas-data release (ATLAS.yaml v5.6.0): AML.T0051 "LLM Prompt
Injection" with sub-techniques .000 "Direct" and .001 "Indirect",
AML.T0056 "Extract LLM System Prompt", AML.T0057 "LLM Data Leakage".

OWASP categories use the 2025 edition of the LLM Top 10. Note that the
2023 edition numbered things differently (LLM02:2023 was "Insecure
Output Handling"); always cite the edition alongside the number.
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
    "context-leakage-system-prompt": {
        "owasp_llm_top10": "LLM07:2025 - System Prompt Leakage",
        "mitre_atlas": "AML.T0056 - Extract LLM System Prompt",
        "description": (
            "The assistant reveals its hidden system prompt or confidential values "
            "planted in it (here: a staff override code)."
        ),
    },
    "prompt-injection-direct": {
        "owasp_llm_top10": "LLM01:2025 - Prompt Injection",
        "mitre_atlas": "AML.T0051.000 - LLM Prompt Injection: Direct",
        "description": (
            "Crafted user input overrides the model's original instructions, "
            "causing it to follow attacker-supplied instructions instead."
        ),
    },
    "prompt-injection-indirect": {
        "owasp_llm_top10": "LLM01:2025 - Prompt Injection (indirect)",
        "mitre_atlas": "AML.T0051.001 - LLM Prompt Injection: Indirect",
        "description": (
            "Instructions hidden inside content the model processes (a review, an "
            "email, a web page) are executed as if they came from the user."
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
