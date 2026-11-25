# SentinelAI Attack Harness

Aman Verma's Semester 7 deliverable for the SentinelAI final year project
(context/session leakage + prompt injection attack harness, taxonomy
mapping, curated mitigations). Aditi Soni's Adaptive Multi-Factor Risk
Scoring Engine plugs into this via the `risk_score` / `risk_factors`
fields on `AttackResult` (see `attacks/base.py`) - this harness produces
the `success`/`evidence` signal the scoring engine consumes, it does not
try to duplicate the scoring engine's job.

## What's actually implemented and tested here

- **Two real, working attacks**, not stubs:
  - `ContextLeakageAttack` - simulates an account switch within one
    session and checks whether a previous account's data leaks into
    the new one. Directly generalises the disclosed Priceline/Penny
    HackerOne finding.
  - `PromptInjectionAttack` - runs a 3-payload injection library
    (direct override, delimiter confusion, role-play override) and
    checks for a unique canary string in the reply.
- **Three model adapters**: `MockAdapter` (deterministic, offline,
  no dependencies - see below), `OllamaAdapter` (self-hosted models,
  the project's primary testbed), `HuggingFaceAdapter` (local
  `transformers` models).
- **Taxonomy mapping** to OWASP LLM Top 10 and MITRE ATLAS, with the
  ATLAS technique IDs (AML.T0051, AML.T0057) verified against current
  published MITRE documentation.
- **A curated mitigation catalogue** (not LLM-generated - this was a
  deliberate scope decision, see the project synopsis).
- **7 passing unit/integration tests** (`pytest tests/`).

## Why there's a Mock adapter

There's no live model endpoint available in most demo/presentation
settings, and pytest shouldn't depend on one either. `MockAdapter` is a
small, deterministic scripted "model" with two configurable profiles:

- `vulnerable` - backend memory persists across `reset_session()` and
  the model complies with injection payloads (mirrors a real
  vulnerable deployment)
- `safe` - backend memory is session-scoped and injection payloads are
  refused (mirrors a hardened deployment)

Running the harness against both profiles proves the detection logic
actually discriminates vulnerable from safe behaviour - this is what
you want to show in a presentation before real model results exist.
**It is not a substitute for real findings** - it's the harness's own
test fixture. Real findings come from `--adapter ollama` against
self-hosted models, per the synopsis's execution plan.

## Quick start

```bash
pip install -r requirements.txt

# Run the test suite
pytest tests/ -v

# Offline demo - no model needed
python -m sentinelai_harness.cli --adapter mock --profile vulnerable
python -m sentinelai_harness.cli --adapter mock --profile safe

# Against a real self-hosted model (once Ollama is installed and a model pulled)
ollama pull llama3.1
python -m sentinelai_harness.cli --adapter ollama --model llama3.1
```

Each run writes `report.json` (structured, for the scoring engine /
further analysis) and `report.md` (human-readable, screenshot-ready
for slides).

## Project layout

```
sentinelai_harness/
  adapters/
    base.py              ModelAdapter interface (send/reset_session)
    mock_adapter.py       Deterministic offline "model" for demo/tests
    ollama_adapter.py      Self-hosted models via Ollama (primary testbed)
    huggingface_adapter.py Local transformers models
  attacks/
    base.py               Attack interface + AttackResult
    context_leakage.py    Cross-account leakage attack
    prompt_injection.py   Injection payload library + attack
  taxonomy.py             OWASP LLM Top 10 / MITRE ATLAS mapping
  mitigations.py          Curated mitigation catalogue
  harness.py              Orchestrator / plugin registry
  report.py               JSON + Markdown report generation
  cli.py                  Command-line entry point
tests/                    7 passing tests, run against MockAdapter
```

## Explicitly out of scope (see synopsis Section 1.3)

Jailbreak libraries, RAG poisoning, and multimodal attacks are not
implemented here - the project is deliberately scoped to two
vulnerability classes so they can be evaluated with depth. Adding a new
attack class later is a matter of subclassing `Attack` and registering
it with `Harness` - the plugin-registry shape already supports it.

## What's NOT in this harness (by design)

The Adaptive Multi-Factor Risk Score (attack success + context leakage
+ response similarity + instruction-following + policy violation,
combined and validated against human judgement) is Aditi's module, not
duplicated here. `AttackResult` has `risk_score` / `risk_factors`
fields reserved for it to populate.
