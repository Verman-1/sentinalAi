"""
Small, curated set of standard mitigations per vulnerability class.

Deliberately NOT an LLM-generated, freeform explanation per finding -
see the project synopsis (Section 1.3 / review discussion): unvalidated
auto-generated mitigations were identified as a research-risk and cut
from scope. A fixed, reviewable catalogue is boring but defensible.
"""

MITIGATIONS = {
    "context-leakage-account-switch": [
        "Scope conversational memory/RAG context to an authenticated session token, "
        "not a browser/client instance.",
        "Explicitly clear or re-key backend memory on every account-switch or login event.",
        "Add automated tests that assert no entity from session A appears in session B's output.",
    ],
    "context-leakage-system-prompt": [
        "Never place secrets (codes, keys, credentials) in the system prompt; keep them "
        "server-side behind authorisation checks.",
        "Filter outputs for system-prompt fragments and planted canary tokens before they reach the user.",
        "Treat the system prompt as public: enforce security in application logic, not in prompt wording.",
    ],
    "prompt-injection-direct": [
        "Enforce an instruction hierarchy: system prompt cannot be overridden by user-turn content.",
        "Sanitize/filter high-risk phrases (e.g. 'ignore previous instructions') at the input layer.",
        "Use a separate, non-generative classifier to flag suspected injection attempts before "
        "they reach the primary model.",
    ],
    "prompt-injection-indirect": [
        "Mark untrusted content explicitly (delimiters/datamarking) and instruct the model to treat "
        "it as data, never as instructions.",
        "Strip hidden markup (HTML comments, invisible text) from documents before they reach the model.",
        "Apply least privilege: content-processing tasks (summarise, translate) must not be able to "
        "trigger actions or change the assistant's behaviour.",
    ],
}


def lookup(attack_id: str) -> list[str]:
    return MITIGATIONS.get(attack_id, [])
