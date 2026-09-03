"""
Command-line entry point.

Examples:
    # Offline demo, no model needed:
    python -m sentinelai_harness.cli --adapter mock --profile vulnerable

    # Against a real local model via Ollama:
    python -m sentinelai_harness.cli --adapter ollama --model llama3.1
"""

import argparse
import sys

from .harness import Harness
from .adapters.mock_adapter import MockAdapter
from . import report


def build_adapter(args):
    if args.adapter == "mock":
        vulnerable = args.profile != "safe"
        return MockAdapter(
            model_name=f"mock-{args.profile}",
            vulnerable_to_leakage=vulnerable,
            vulnerable_to_injection=vulnerable,
        )
    if args.adapter == "ollama":
        from .adapters.ollama_adapter import OllamaAdapter
        return OllamaAdapter(model_name=args.model or "llama3.1")
    if args.adapter == "huggingface":
        from .adapters.huggingface_adapter import HuggingFaceAdapter
        if not args.model:
            print("--model is required for the huggingface adapter", file=sys.stderr)
            sys.exit(1)
        return HuggingFaceAdapter(model_name=args.model)
    raise ValueError(f"Unknown adapter: {args.adapter}")


def main():
    parser = argparse.ArgumentParser(description="SentinelAI attack harness")
    parser.add_argument("--adapter", choices=["mock", "ollama", "huggingface"], default="mock")
    parser.add_argument("--model", default=None, help="Model name (for ollama/huggingface)")
    parser.add_argument("--profile", choices=["vulnerable", "safe"], default="vulnerable",
                         help="Only used with --adapter mock")
    parser.add_argument("--json-out", default="report.json")
    parser.add_argument("--md-out", default="report.md")
    args = parser.parse_args()

    adapter = build_adapter(args)
    harness = Harness()
    findings = harness.run_all_annotated(adapter)

    report.write_json(findings, args.json_out)
    report.write_markdown(findings, adapter.model_name, args.md_out)

    n_success = sum(1 for f in findings if f["success"])
    print(f"Ran {len(findings)} attacks against '{adapter.model_name}'. "
          f"{n_success} confirmed finding(s). Reports written to {args.json_out} and {args.md_out}.")


if __name__ == "__main__":
    main()
