"""
Command-line entry point: run every attack against ONE target and write
report.json / report.md. For multi-model benchmarks with trials,
statistics and an HTML report, use `python -m sentinelai_harness.bench`.

Examples:
    # Offline demo, no model needed (legacy single-object mock):
    python -m sentinelai_harness.cli --adapter mock --profile vulnerable

    # Scripted model behind the vulnerable TravelAssist app:
    python -m sentinelai_harness.cli --adapter scripted --profile partial --app vulnerable

    # A real local model via Ollama, behind the vulnerable app:
    python -m sentinelai_harness.cli --adapter ollama --model llama3.2:3b --app vulnerable
"""

import argparse
import sys

from .harness import Harness
from .adapters.mock_adapter import MockAdapter
from .scoring.engine import SENSITIVITY, RiskScoringEngine
from .targets.travel_app import APP_CONFIGS, TravelAssistApp
from . import report

PROFILE_CHOICES = ["vulnerable", "safe", "naive", "hardened", "partial", "quoting"]


def build_adapter(args):
    if args.adapter == "mock":
        if args.profile not in ("vulnerable", "safe"):
            print("--adapter mock supports --profile vulnerable or safe", file=sys.stderr)
            sys.exit(1)
        vulnerable = args.profile != "safe"
        return MockAdapter(
            model_name=f"mock-{args.profile}",
            vulnerable_to_leakage=vulnerable,
            vulnerable_to_injection=vulnerable,
        )
    if args.adapter == "scripted":
        from .adapters.scripted_llm import ScriptedLLM
        base = ScriptedLLM({"vulnerable": "naive", "safe": "hardened"}.get(args.profile, args.profile))
    elif args.adapter == "ollama":
        from .adapters.ollama_adapter import OllamaAdapter
        base = OllamaAdapter(model_name=args.model or "llama3.2:3b", temperature=args.temperature, seed=args.seed)
    elif args.adapter == "huggingface":
        from .adapters.huggingface_adapter import HuggingFaceAdapter
        if not args.model:
            print("--model is required for the huggingface adapter", file=sys.stderr)
            sys.exit(1)
        base = HuggingFaceAdapter(model_name=args.model)
    else:
        raise ValueError(f"Unknown adapter: {args.adapter}")
    if args.app == "none":
        return base
    return TravelAssistApp(base, **APP_CONFIGS[args.app])


def main():
    parser = argparse.ArgumentParser(description="SentinelAI attack harness - single target run")
    parser.add_argument("--adapter", choices=["mock", "scripted", "ollama", "huggingface"], default="mock")
    parser.add_argument("--model", default=None, help="Model name (for ollama/huggingface)")
    parser.add_argument("--profile", choices=PROFILE_CHOICES, default="vulnerable",
                        help="mock: vulnerable|safe; scripted: naive|hardened|partial|quoting")
    parser.add_argument("--app", choices=["none", *APP_CONFIGS], default="none",
                        help="Wrap the model in the TravelAssist app (needed for cross-account leakage)")
    parser.add_argument("--sensitivity", choices=sorted(SENSITIVITY), default="standard",
                        help="Deployment sensitivity for the risk engine")
    parser.add_argument("--temperature", type=float, default=0.7)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--json-out", default="report.json")
    parser.add_argument("--md-out", default="report.md")
    args = parser.parse_args()

    adapter = build_adapter(args)
    harness = Harness(engine=RiskScoringEngine(deployment_sensitivity=args.sensitivity))
    findings = harness.run_all_annotated(adapter)

    report.write_json(findings, args.json_out)
    report.write_markdown(findings, adapter.model_name, args.md_out)

    n_success = sum(1 for f in findings if f["success"])
    print(f"Target: {adapter.model_name}")
    for f in findings:
        status = "VULNERABLE" if f["success"] else "resisted  "
        print(f"  {f['attack_name']:<32} {status}  risk {f['risk_score']:5.1f} {f['severity']:<8} "
              f"({f['attack_success_rate']:.0%} of probes)")
    print(f"Ran {len(findings)} attacks against '{adapter.model_name}'. "
          f"{n_success} confirmed finding(s). Reports written to {args.json_out} and {args.md_out}.")


if __name__ == "__main__":
    main()
