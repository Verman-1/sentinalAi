"""
SentinelAI Attack Harness
=========================

Automated red-teaming harness for two LLM vulnerability classes:
  1. Context / session leakage (cross-account data persistence)
  2. Prompt injection (instruction override)

This package implements Aman Verma's half of the SentinelAI system
(see /areas/sentinelai-project for the full project scope). It plugs
into a model adapter (Ollama, HuggingFace, or a deterministic Mock
adapter for offline testing/demo) and produces structured findings
mapped to the OWASP LLM Top 10 and MITRE ATLAS taxonomies, with a
hook point for the Adaptive Multi-Factor Risk Scoring engine
(Aditi Soni's half) to plug into.
"""

__version__ = "0.1.0"
