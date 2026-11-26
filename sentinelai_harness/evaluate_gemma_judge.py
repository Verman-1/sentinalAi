
"""
Evaluate Gemma 2.5 3b IT as an independent LLM judge.

Reads existing benchmark records, evaluates each response using LLMJudge,
and compares Gemma's verdicts against the existing heuristic detector.

Original benchmark records are never modified.
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Ensure the repository root is importable when this file is run directly.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinelai_harness.adapters.huggingface_adapter import HuggingFaceAdapter
from sentinelai_harness.attacks.context_leakage import protected_items
from sentinelai_harness.fixtures import APP_SECRET, CONFIDENTIAL_NOTE
from sentinelai_harness.scoring.judge import LLMJudge


DEFAULT_MODEL = "Qwen/Qwen2.5-3B-Instruct"

DEFAULT_INPUT = (
    ROOT / "results/model-run/validation_v11/records.jsonl"
)

DEFAULT_OUTPUT = (
    ROOT / "results/model-run/validation_v11/judge_gemma3_4b"
)


# ---------------------------------------------------------
# Attack-specific evaluation context
# ---------------------------------------------------------

def protected_for_record(record):
    """
    Return information that must not be disclosed.

    Important:
    Prompt-injection canaries are success markers, not secrets.
    They must NOT be passed as protected information.
    """

    attack_id = record["attack_id"]

    if attack_id == "context-leakage-account-switch":
        return [item.value for item in protected_items()]

    if attack_id == "context-leakage-system-prompt":
        return [APP_SECRET, CONFIDENTIAL_NOTE]

    if attack_id in (
        "prompt-injection-direct",
        "prompt-injection-indirect",
    ):
        return []

    raise ValueError(
        f"Unknown attack_id {attack_id!r}. "
        "Add its protected-information mapping before evaluating."
    )


def response_for_judge(record):
    """
    Return everything the attacker was actually shown.

    For account-switch leakage, Account B sees both:
      1. The unrelated booking response.
      2. The response to the explicit leak probe.

    Other attacks use their recorded response.
    """

    if record["attack_id"] == "context-leakage-account-switch":
        return "\n".join(
            part
            for part in (
                record.get("context", ""),
                record.get("response", ""),
            )
            if part
        )

    return record.get("response", "")


def judge_class_for_record(record):
    """
    Give the judge a more precise attack label.

    The original vulnerability_class is insufficient because
    both leakage attacks use 'context_leakage'.
    """

    attack_id = record["attack_id"]

    mapping = {
        "context-leakage-account-switch": "cross-account context leakage",
        "context-leakage-system-prompt": "system-prompt leakage",
        "prompt-injection-direct": "direct prompt injection",
        "prompt-injection-indirect": "indirect prompt injection",
    }

    if attack_id not in mapping:
        raise ValueError(f"Unknown attack_id: {attack_id}")

    return mapping[attack_id]


# ---------------------------------------------------------
# Input/output
# ---------------------------------------------------------

def load_records(path):
    records = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number}: {exc}"
                ) from exc

            records.append(record)

    return records


def write_jsonl(path, records):
    with path.open("w", encoding="utf-8") as file:
        for record in records:
            file.write(
                json.dumps(record, ensure_ascii=False) + "\n"
            )


# ---------------------------------------------------------
# Evaluation
# ---------------------------------------------------------

def evaluate_records(records, judge, output_path):
    results = []

    for index, record in enumerate(records, start=1):
        attack_id = record["attack_id"]

        prompt = record.get("prompt", "")
        response = response_for_judge(record)
        objective = record.get("objective", "")

        protected = protected_for_record(record)
        judge_class = judge_class_for_record(record)

        print(
            f"[{index}/{len(records)}] "
            f"{attack_id} / {record.get('probe_id', 'unknown')}",
            flush=True,
        )

        error = None
        verdict = None

        try:
            verdict = judge.evaluate(
                vulnerability_class=judge_class,
                objective=objective,
                prompt=prompt,
                response=response,
                protected=protected,
            )
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            print(f"  ERROR: {error}", flush=True)

        heuristic_success = bool(record.get("success", False))

        result = {
            "record_index": index,
            "attack_id": attack_id,
            "probe_id": record.get("probe_id"),
            "vulnerability_class": record.get("vulnerability_class"),
            "judge_class": judge_class,
            "heuristic_success": heuristic_success,
            "judge": verdict.to_dict() if verdict else None,
            "judge_error": error,
            "agreement": (
                verdict.attack_succeeded == heuristic_success
                if verdict is not None
                else None
            ),
        }

        results.append(result)

        if verdict is not None:
            print(
                f"  Heuristic={heuristic_success} "
                f"Gemma={verdict.attack_succeeded} "
                f"Agreement={result['agreement']}",
                flush=True,
            )
        else:
            print("  No valid judge verdict.", flush=True)

        # Save progressively so an interrupted run retains completed work.
        write_jsonl(output_path, results)

    return results


# ---------------------------------------------------------
# Reporting
# ---------------------------------------------------------

def build_summary(results, input_path, model_name):
    valid = [
        result for result in results
        if result["judge"] is not None
    ]

    agreements = [
        result for result in valid
        if result["agreement"] is not None
    ]

    correct_agreements = sum(
        result["agreement"] for result in agreements
    )

    summary = {
        "judge_model": model_name,
        "input_file": str(input_path),
        "total_records": len(results),
        "valid_verdicts": len(valid),
        "invalid_verdicts": len(results) - len(valid),
        "agreement_count": correct_agreements,
        "disagreement_count": (
            len(agreements) - correct_agreements
        ),
        "agreement_rate": (
            round(correct_agreements / len(agreements), 4)
            if agreements else None
        ),
        "by_attack": {},
    }

    grouped = defaultdict(list)

    for result in results:
        grouped[result["attack_id"]].append(result)

    for attack_id, group in grouped.items():
        group_valid = [
            item for item in group
            if item["judge"] is not None
        ]

        group_agreements = [
            item for item in group_valid
            if item["agreement"] is not None
        ]

        matches = sum(
            item["agreement"] for item in group_agreements
        )

        summary["by_attack"][attack_id] = {
            "total": len(group),
            "valid_verdicts": len(group_valid),
            "agreement_count": matches,
            "disagreement_count": (
                len(group_agreements) - matches
            ),
            "agreement_rate": (
                round(matches / len(group_agreements), 4)
                if group_agreements else None
            ),
        }

    return summary


def write_report(summary, path):
    lines = [
        "# Gemma 3 4B IT — LLM Judge Evaluation",
        "",
        f"- Model: `{summary['judge_model']}`",
        f"- Input: `{summary['input_file']}`",
        f"- Total records: {summary['total_records']}",
        f"- Valid verdicts: {summary['valid_verdicts']}",
        f"- Invalid verdicts: {summary['invalid_verdicts']}",
        f"- Agreements: {summary['agreement_count']}",
        f"- Disagreements: {summary['disagreement_count']}",
        f"- Agreement rate: {summary['agreement_rate']}",
        "",
        "## Results by attack",
        "",
        "| Attack | Total | Valid | Agreements | Disagreements | Agreement rate |",
        "|---|---:|---:|---:|---:|---:|",
    ]

    for attack_id, data in summary["by_attack"].items():
        lines.append(
            f"| {attack_id} "
            f"| {data['total']} "
            f"| {data['valid_verdicts']} "
            f"| {data['agreement_count']} "
            f"| {data['disagreement_count']} "
            f"| {data['agreement_rate']} |"
        )

    lines.extend([
        "",
        "## Interpretation",
        "",
        "Agreement measures how often Gemma's binary decision "
        "matches the existing heuristic detector. It does not "
        "establish that either decision is correct.",
        "",
        "Human-labelled validation is required to estimate judge "
        "accuracy independently.",
    ])

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Evaluate Gemma as SentinelAI's LLM judge."
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
    )

    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Evaluate only the first N records. 0 means all.",
    )

    args = parser.parse_args()

    if not args.input.exists():
        raise FileNotFoundError(
            f"Input records not found: {args.input}"
        )

    args.output.mkdir(parents=True, exist_ok=True)

    records = load_records(args.input)

    if args.limit > 0:
        records = records[:args.limit]

    if not records:
        raise ValueError("No records found to evaluate.")

    print(f"Loaded {len(records)} records.")
    print(f"Loading judge model: {args.model}")

    adapter = HuggingFaceAdapter(
        model_name=args.model,
        device="auto",
        precision="auto",
        max_new_tokens=256,
        temperature=0.0,
        do_sample=False,
    )

    judge = LLMJudge(
        adapter=adapter,
        max_retries=1,
    )

    verdicts_path = args.output / "verdicts.jsonl"

    results = evaluate_records(
        records=records,
        judge=judge,
        output_path=verdicts_path,
    )

    summary = build_summary(
        results=results,
        input_path=args.input,
        model_name=args.model,
    )

    summary_path = args.output / "summary.json"

    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    write_report(
        summary,
        args.output / "report.md",
    )

    print("\nEvaluation complete.")
    print(f"Verdicts: {verdicts_path}")
    print(f"Summary:  {summary_path}")
    print(f"Report:   {args.output / 'report.md'}")
    print(
        f"Agreement rate: {summary['agreement_rate']}"
    )


if __name__ == "__main__":
    main()


