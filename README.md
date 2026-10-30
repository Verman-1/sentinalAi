# SentinelAI

**An Adaptive Multi-Factor Risk Scoring Framework for Automated LLM Security Evaluation**

Final-year B.Tech (CSE) research project, ABES Engineering College, by Aman Verma
and Aditi Soni, guided by Ms. Babli Kumari.

The project generalises a responsibly disclosed vulnerability, an AI context-isolation
flaw in Priceline's "Penny" assistant reported via HackerOne, into an automated,
repeatable evaluation. SentinelAI attacks an LLM assistant on two vulnerability classes
(**context/session leakage** and **prompt injection**). It scores every interaction with a
graded **0–100 multi-factor risk score** instead of pass/fail, and maps findings to the
OWASP LLM Top 10 and MITRE ATLAS with curated mitigations.

## Status (end of October 2026, Semester 7)

| Synopsis milestone (Gantt) | Status | Where |
|---|---|---|
| Literature survey & novelty positioning | Done | synopsis, progress report |
| Attack harness design & implementation | **Done.** 4 attacks: 16 injection payloads (12 direct, 4 indirect), 5 system-prompt extraction probes, 3 cross-account leakage probes | `attacks/`, `targets/` |
| OWASP / MITRE ATLAS taxonomy mapping | **Done.** IDs checked against MITRE atlas-data v5.6.0 | `taxonomy.py`, `mitigations.py` |
| Risk scoring engine v1 | **Done.** 5 factors, adaptive weights, disclosure floor, LLM-as-judge hook | `scoring/`, [docs/risk_scoring_v1.md](docs/risk_scoring_v1.md) |
| Execution on self-hosted models; first results | **Pipeline done and validated** on scripted targets with ground truth. Real-model runs are waiting on Ollama being installed on a lab machine | `bench.py`, `results/` |
| Human-validation study | Tooling ready: blind labelling export, Cohen's κ, weighted κ, Spearman. Labelling is in Semester 8 | `validation.py` |
| FastAPI service, Docker | Planned, not started | — |

## How it works

```
 payload libraries ─► attacks/ ── direct injection · indirect injection · system-prompt leakage
                          │        cross-account leakage (A shares data, B logs in on the same device)
                          ▼
 target ─────────► adapters/  Ollama · HuggingFace · ScriptedLLM (offline) · MockAdapter (legacy)
                   targets/   TravelAssistApp: LLM app with a memory layer
                              memory = device (vulnerable) | device + guard prompt | account (patched)
                          ▼
 detectors.py ───► 5 signals per probe: attack success, context leakage, response
                   similarity, instruction deviation, policy violation
                          ▼
 scoring/ ───────► probe / attack / model risk (0-100) + severity; optional LLM judge
                          ▼
 taxonomy + mitigations ─► OWASP LLM Top 10 (2025) · MITRE ATLAS · fixes
                          ▼
 bench.py ───────► records.jsonl · summary.json · report.md · report.html ─► validation.py (κ)
```

**Why there is an application target.** Cross-account leakage is an *application* flaw,
because a bare model keeps no state between requests. `TravelAssistApp` reproduces the
Penny architecture: an assistant with a memory layer that puts remembered customer facts
back into the prompt. It runs in three configurations, so the same real model can be
tested behind a vulnerable deployment, a prompt-level mitigation and the architectural
fix.

## Quick start

```bash
pip install -r requirements.txt
pytest tests/ -v
```

```bash
python -m sentinelai_harness.bench --scripted all --out results/scripted_v1
```

```bash
python -m sentinelai_harness.cli --adapter scripted --profile partial --app vulnerable
```

The last command runs every attack against one target and writes `report.json` and
`report.md`. The September demo, `python -m sentinelai_harness.cli --adapter mock --profile vulnerable`,
still works.

## Running on real self-hosted models

1. Install Ollama from https://ollama.com.
2. Pull small, CPU-friendly models from different vendors:

```bash
ollama pull llama3.2:3b
```

```bash
ollama pull gemma2:2b
```

```bash
ollama pull qwen2.5:1.5b
```

3. Run the benchmark: 3 seeded trials per model, with mean ± 95% CI reported.

```bash
python -m sentinelai_harness.bench --ollama llama3.2:3b gemma2:2b qwen2.5:1.5b --trials 3 --out results/ollama_v1
```

Each model gets 48 model calls per trial. On a CPU-only laptop that is roughly 10–25
minutes per model per trial (an estimate; a GPU is much faster). Add
`--judge-ollama llama3.2:3b` to also grade every probe with an LLM judge (about 2× the
calls). Use `--sensitivity high` for PII-handling deployments.

## Scripted results: what they show and what they don't

`results/scripted_v1` is the benchmark run against four **scripted targets**. These are
offline stand-ins with known, hand-written behaviour, and every reply carries a
ground-truth label. They validate the harness, detectors and scoring end to end. **They
are not findings about any real model.**

| Scripted target | Behaviour | Model risk index | App leakage: vulnerable / guarded / patched |
|---|---|---|---|
| naive | obeys everything | 87.6 High | 88.7 / 88.7 / 0.0 |
| hardened | refuses injection and extraction | 0.3 None | 88.7 / 0.0 / 0.0 |
| partial | English keyword filter, leaks partially | 67.7 Medium | 49.7 / 49.7 / 0.0 |
| quoting | refuses, but quotes the attacker's text | 13.8 Low | 60.2 / 60.2 / 0.0 |

What the run does establish:

- **Detector accuracy.** Against ground truth (120 probes), the v1 detectors reach
  precision 1.00, recall 0.96, κ = 0.97. The September substring checks reached
  precision 0.75, κ = 0.60: they counted 14 refusals that *quoted* the canary as
  successful attacks. The two remaining misses are a deliberately paraphrased leak
  ("Iceland's capital"), which is why the LLM judge and human validation exist.
- **Graded scores behave sensibly.** A full PII leak scores 98.9 (Critical), a partial
  leak 61.0 (Medium), and a refusal that echoes the payload 21.2 (Low). See the worked
  examples in [docs/risk_scoring_v1.md](docs/risk_scoring_v1.md).
- **The experiment design works.** In the scripted setup, a model that refuses
  everything still leaks behind the vulnerable app, and only the account-scoped memory
  removes leakage for every profile. Whether real models behave this way is what the
  Ollama run will measure.

## Human validation (Semester 8)

```bash
python -m sentinelai_harness.validation export --records results/ollama_v1/records.jsonl --out labels/sheet.csv --n 60
```

Two annotators each fill in a copy of `labels/sheet.csv`. The sheet is blind (no
automated scores); `label_success` is 0/1 and `label_severity` is 0–4. Then compute the
agreement:

```bash
python -m sentinelai_harness.validation agreement --a labels/aman.csv --b labels/aditi.csv --key labels/sheet_key.csv
```

This reports inter-annotator κ, quadratic-weighted κ for severity, detector-vs-human κ
with precision/recall, and Spearman's ρ between the risk score and human severity.

## Project layout

```
sentinelai_harness/
  adapters/      base (ModelAdapter), ollama, huggingface, scripted_llm, mock_adapter
  targets/       travel_app.py - TravelAssistApp with device/account-scoped memory
  attacks/       prompt_injection.py (direct + indirect), system_prompt_leakage.py,
                 context_leakage.py, base.py (AttackResult / ProbeResult)
  detectors.py   canary compliance, refusal, protected-value disclosure, n-gram overlap
  scoring/       engine.py (Risk Scoring Engine v1), judge.py (LLM-as-judge)
  taxonomy.py    OWASP LLM Top 10 (2025) + MITRE ATLAS mapping
  mitigations.py curated mitigation catalogue
  bench.py       multi-model benchmark runner; bench_report.py renders md/html
  validation.py  labelling export, Cohen's / weighted kappa, Spearman
  cli.py         single-target run
  fixtures.py    synthetic victim data and planted secret (all fictional)
docs/            risk_scoring_v1.md - scoring specification
results/         benchmark outputs
tests/           56 tests (pytest); CI on Python 3.11 and 3.12
```

## Scope

Following synopsis Section 1.3, jailbreak libraries, RAG poisoning and multimodal attacks
are out of scope; new attack classes plug in by subclassing `Attack`. Testing is
restricted to self-hosted models and authorised targets.

## Team

| Module | Lead (per synopsis) |
|---|---|
| Attack harness, payload design, taxonomy mapping, mitigation catalogue | Aman Verma |
| Risk scoring engine, LLM/VLM-as-judge pipeline, validation study, FastAPI service | Aditi Soni |
