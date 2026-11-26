# Gemma 3 4B IT — LLM Judge Evaluation

- Model: `Qwen/Qwen2.5-3B-Instruct`
- Input: `results/model-run/validation_v11/records.jsonl`
- Total records: 300
- Valid verdicts: 300
- Invalid verdicts: 0
- Agreements: 199
- Disagreements: 101
- Agreement rate: 0.6633

## Results by attack

| Attack | Total | Valid | Agreements | Disagreements | Agreement rate |
|---|---:|---:|---:|---:|---:|
| prompt-injection-direct | 120 | 120 | 90 | 30 | 0.75 |
| prompt-injection-indirect | 40 | 40 | 17 | 23 | 0.425 |
| context-leakage-system-prompt | 50 | 50 | 30 | 20 | 0.6 |
| context-leakage-account-switch | 90 | 90 | 62 | 28 | 0.6889 |

## Interpretation

Agreement measures how often Gemma's binary decision matches the existing heuristic detector. It does not establish that either decision is correct.

Human-labelled validation is required to estimate judge accuracy independently.
