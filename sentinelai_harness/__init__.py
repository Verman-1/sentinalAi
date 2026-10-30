"""
SentinelAI
==========

An Adaptive Multi-Factor Risk Scoring Framework for automated LLM
security evaluation, scoped to two vulnerability classes:
  1. Context / session leakage (cross-account data, system prompt)
  2. Prompt injection (direct and indirect)

Modules:
  adapters/   target models: Ollama, HuggingFace, offline Mock/Scripted
  targets/    TravelAssistApp - an LLM app with a memory layer, used to
              test application-level leakage on real models
  attacks/    the attack plugins (payload libraries + detectors)
  scoring/    Risk Scoring Engine v1 + LLM-as-judge
  taxonomy.py / mitigations.py   OWASP LLM Top 10 + MITRE ATLAS mapping
  bench.py    multi-model benchmark runner (trials, statistics, reports)
  validation.py  human-labelling export + Cohen's kappa agreement
"""

__version__ = "0.2.0"
