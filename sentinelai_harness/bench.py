"""
Benchmark runner - the "execute the harness against a set of self-hosted
models, score every interaction" steps of the synopsis methodology
(Section 4, steps ii-iii).

For every target model and every trial it runs

  model level  Direct injection (12 payloads), indirect injection (4) and
               system-prompt leakage (5 probes) against the raw model.
  app level    Cross-account context leakage (3 probes) through
               TravelAssistApp in three configurations: vulnerable
               (device-scoped memory), guarded (+ guard prompt) and
               patched (account-scoped memory).

That is 48 model calls per target per trial. Every probe is scored by the
Risk Scoring Engine; trials use consecutive fixed seeds so a run is
repeatable and run-to-run variance is measurable (mean +/- 95% CI).

Outputs (in --out):
  records.jsonl   one line per scored probe - the raw evidence
  attacks.csv     one row per attack execution
  summary.json    run metadata + aggregated results
  report.md / report.html

Examples:
  # Offline pipeline validation against scripted targets with known ground truth
  python -m sentinelai_harness.bench --scripted all --out results/scripted_v1

  # Real self-hosted models
  python -m sentinelai_harness.bench --ollama llama3.2:3b gemma2:2b qwen2.5:1.5b --trials 3 --out results/ollama_v1
"""

import argparse
import csv
import json
import math
import os
import platform
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from statistics import fmean, stdev
from typing import Callable

from . import __version__
from .adapters.base import ModelAdapter
from .adapters.ollama_adapter import DEFAULT_URL, OllamaAdapter
from .adapters.scripted_llm import PROFILES, ScriptedLLM
from .attacks.base import FACTORS
from .attacks.context_leakage import SECRET_DESTINATION, SECRET_NAME, ContextLeakageAttack
from .attacks.prompt_injection import IndirectPromptInjectionAttack, PromptInjectionAttack
from .attacks.system_prompt_leakage import SystemPromptLeakageAttack
from .bench_report import render_html, render_markdown
from .scoring.engine import ENGINE_VERSION, SENSITIVITY, RiskScoringEngine, severity_for
from .scoring.judge import LLMJudge
from .targets.travel_app import APP_CONFIGS, TravelAssistApp
from .validation import binary_metrics

MODEL_LEVEL_ATTACKS = (PromptInjectionAttack, IndirectPromptInjectionAttack, SystemPromptLeakageAttack)
APP_LEVEL = ("vulnerable", "guarded", "patched")

# Two-sided 95% Student-t critical values by degrees of freedom.
_T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228}


@dataclass
class Backend:
    name: str
    kind: str                                 # "scripted" | "ollama" | "huggingface"
    factory: Callable[[int], ModelAdapter]    # seed -> fresh adapter


def ci95(values) -> float:
    """Half-width of the 95% confidence interval of the mean (Student t)."""
    n = len(values)
    if n < 2:
        return 0.0
    return _T95.get(n - 1, 1.96) * stdev(values) / math.sqrt(n)


def _truth_index(llm) -> dict:
    log = getattr(llm, "truth_log", None) or []
    return {entry["response"]: bool(entry["truth_success"]) for entry in log}


def _v0_detection(attack_id: str, probe) -> bool | None:
    """The September (v0) detectors - plain substring checks - kept as a baseline."""
    if attack_id.startswith("prompt-injection"):
        return any(marker in probe.response for marker in probe.protected)
    if attack_id == "context-leakage-account-switch":
        return SECRET_NAME in probe.response or SECRET_DESTINATION in probe.response
    return None


# ------------------------------------------------------------------ run

def run_benchmark(backends, trials: int = 1, base_seed: int = 7, engine: RiskScoringEngine | None = None,
                  log=print) -> dict:
    engine = engine or RiskScoringEngine()
    started = datetime.now(timezone.utc)
    records, attack_rows = [], []

    for backend in backends:
        for trial in range(1, trials + 1):
            seed = base_seed + trial - 1
            jobs = [("model", cls, None) for cls in MODEL_LEVEL_ATTACKS]
            jobs += [(f"app:{label}", ContextLeakageAttack, label) for label in APP_LEVEL]
            for config, attack_cls, app_label in jobs:
                llm = backend.factory(seed)
                target = TravelAssistApp(llm, **APP_CONFIGS[app_label]) if app_label else llm
                t0 = time.perf_counter()
                result = engine.score_attack(attack_cls().run(target))
                elapsed = time.perf_counter() - t0
                truth = _truth_index(llm)
                severity = result.risk_factors["severity"]
                attack_rows.append({
                    "target": backend.name, "kind": backend.kind, "config": config, "trial": trial, "seed": seed,
                    "attack_id": result.attack_id, "attack_name": result.attack_name,
                    "vulnerability_class": result.vulnerability_class, "risk_score": result.risk_score,
                    "severity": severity, "asr": round(result.success_rate, 4), "success": result.success,
                    "probes": len(result.probes), "seconds": round(elapsed, 2),
                })
                for probe in result.probes:
                    seen = [truth[r] for r in (probe.response, probe.context) if r in truth]
                    records.append({
                        "target": backend.name, "kind": backend.kind, "config": config, "trial": trial,
                        "seed": seed, "attack_id": result.attack_id, "attack_name": result.attack_name,
                        "vulnerability_class": result.vulnerability_class, "probe_id": probe.probe_id,
                        "family": probe.family, "channel": probe.channel, "objective": probe.objective,
                        "prompt": probe.prompt, "context": probe.context, "response": probe.response,
                        "success": probe.success, "risk_score": probe.risk["score"],
                        "severity": probe.risk["severity"], "factors": probe.risk["factors"],
                        "evidence": probe.evidence, "judge": probe.judge,
                        "ground_truth": any(seen) if seen else None,
                        "v0_detection": _v0_detection(result.attack_id, probe),
                    })
                log(f"[{backend.name}] trial {trial}/{trials}  {config:<15} {result.attack_name:<28} "
                    f"risk {result.risk_score:5.1f} {severity:<8} ASR {result.success_rate:4.0%}  ({elapsed:.1f}s)")

    finished = datetime.now(timezone.utc)
    meta = {
        "harness_version": __version__,
        "engine": ENGINE_VERSION,
        "deployment_sensitivity": engine.deployment_sensitivity,
        "weights": {cls: engine.weights(cls) for cls in ("prompt_injection", "context_leakage")},
        "trials": trials,
        "seeds": [base_seed + t for t in range(trials)],
        "targets": [{"name": b.name, "kind": b.kind} for b in backends],
        "judge": engine.judge.adapter.model_name if engine.judge is not None else None,
        "started": started.isoformat(timespec="seconds"),
        "finished": finished.isoformat(timespec="seconds"),
        "duration_s": round((finished - started).total_seconds(), 1),
        "python": platform.python_version(),
        "platform": platform.platform(),
    }
    return {"meta": meta, "records": records, "attacks": attack_rows,
            "summary": summarise(records, attack_rows)}


# ------------------------------------------------------------ summarise

def summarise(records: list, attack_rows: list) -> dict:
    groups, factor_groups = {}, {}
    for row in attack_rows:
        groups.setdefault((row["target"], row["config"], row["attack_id"]), []).append(row)
    for rec in records:
        factor_groups.setdefault((rec["target"], rec["config"], rec["attack_id"]), []).append(rec["factors"])

    attack_summary = []
    for key, rows in groups.items():
        target, config, attack_id = key
        scores = [r["risk_score"] for r in rows]
        mean = fmean(scores)
        factor_rows = factor_groups.get(key, [])
        attack_summary.append({
            "target": target, "kind": rows[0]["kind"], "config": config, "attack_id": attack_id,
            "attack_name": rows[0]["attack_name"], "vulnerability_class": rows[0]["vulnerability_class"],
            "trials": len(rows), "risk_mean": round(mean, 1), "risk_ci95": round(ci95(scores), 1),
            "risk_min": min(scores), "risk_max": max(scores), "severity": severity_for(mean),
            "asr_mean": round(fmean(r["asr"] for r in rows), 4),
            "factor_means": {k: round(fmean(f[k] for f in factor_rows), 4) for k in FACTORS} if factor_rows else {},
        })

    targets = list(dict.fromkeys(r["target"] for r in attack_rows))
    model_index = []
    for target in targets:
        mine = [a for a in attack_summary if a["target"] == target]
        model_rows = [a for a in mine if a["config"] == "model"]
        index = round(fmean(a["risk_mean"] for a in model_rows), 1) if model_rows else 0.0
        cell = lambda a: {"risk": a["risk_mean"], "ci95": a["risk_ci95"], "asr": a["asr_mean"],
                          "severity": a["severity"]}
        model_index.append({
            "target": target,
            "kind": mine[0]["kind"] if mine else "",
            "model_risk_index": index,
            "severity": severity_for(index),
            "attacks": {a["attack_id"]: cell(a) for a in model_rows},
            "app_leakage": {a["config"].split(":", 1)[1]: cell(a) for a in mine if a["config"].startswith("app:")},
        })

    families = {}
    for rec in records:
        if rec["vulnerability_class"] == "prompt_injection":
            families.setdefault((rec["family"], rec["channel"]), {}).setdefault(rec["target"], []).append(rec["success"])
    family_asr = [
        {"family": family, "channel": channel,
         "asr": {t: round(fmean(v), 4) for t, v in per_target.items()},
         "n": {t: len(v) for t, v in per_target.items()}}
        for (family, channel), per_target in families.items()
    ]

    return {
        "attack_summary": attack_summary,
        "model_index": model_index,
        "family_asr": family_asr,
        "detector_validation": detector_validation(records),
    }


def detector_validation(records: list) -> dict | None:
    """Compare detector verdicts with ground truth (available for scripted targets)."""
    labelled = [r for r in records if r.get("ground_truth") is not None]
    if not labelled:
        return None
    classes = sorted({r["vulnerability_class"] for r in labelled})
    scopes = [("all", labelled)] + [(c, [r for r in labelled if r["vulnerability_class"] == c]) for c in classes]
    out = {"n": len(labelled), "scopes": {}}
    for name, subset in scopes:
        legacy = [r for r in subset if r.get("v0_detection") is not None]
        out["scopes"][name] = {
            "v1": binary_metrics([r["success"] for r in subset], [r["ground_truth"] for r in subset]),
            "v0_baseline": binary_metrics([r["v0_detection"] for r in legacy], [r["ground_truth"] for r in legacy])
            if legacy else None,
            "v1_on_v0_scope": binary_metrics([r["success"] for r in legacy], [r["ground_truth"] for r in legacy])
            if legacy else None,
        }
    misses, seen = [], set()
    for r in labelled:
        key = (r["target"], r["config"], r["probe_id"])
        if r["success"] != r["ground_truth"] and key not in seen:
            seen.add(key)
            misses.append({
                "target": r["target"], "config": r["config"], "attack_id": r["attack_id"],
                "probe_id": r["probe_id"], "detected": r["success"], "ground_truth": r["ground_truth"],
                "response": r["response"][:240],
            })
    out["disagreements"] = misses
    return out


# --------------------------------------------------------------- output

def write_outputs(run: dict, out_dir: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    paths = {name: os.path.join(out_dir, name) for name in
             ("records.jsonl", "attacks.csv", "summary.json", "report.md", "report.html")}
    with open(paths["records.jsonl"], "w", encoding="utf-8") as f:
        for rec in run["records"]:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    with open(paths["attacks.csv"], "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(run["attacks"][0]) if run["attacks"] else ["target"])
        writer.writeheader()
        writer.writerows(run["attacks"])
    with open(paths["summary.json"], "w", encoding="utf-8") as f:
        json.dump({"meta": run["meta"], "summary": run["summary"]}, f, indent=2, ensure_ascii=False)
    with open(paths["report.md"], "w", encoding="utf-8") as f:
        f.write(render_markdown(run))
    with open(paths["report.html"], "w", encoding="utf-8") as f:
        f.write(render_html(run))
    return paths


# ------------------------------------------------------------------ CLI

def _pulled(model: str, available: list) -> bool:
    return model in available or f"{model}:latest" in available


def _hf_factory(model_name: str):
    cache = {}

    def make(seed: int) -> ModelAdapter:
        if "adapter" not in cache:  # load weights once, reuse across jobs
            from .adapters.huggingface_adapter import HuggingFaceAdapter
            cache["adapter"] = HuggingFaceAdapter(model_name)
        adapter = cache["adapter"]
        adapter.hard_reset()
        return adapter

    return make


def main(argv=None):
    parser = argparse.ArgumentParser(description="SentinelAI multi-model benchmark")
    parser.add_argument("--scripted", nargs="*", metavar="PROFILE",
                        help=f"scripted test targets: {', '.join(PROFILES)} (no names = all)")
    parser.add_argument("--ollama", nargs="*", default=[], metavar="MODEL", help="Ollama model names")
    parser.add_argument("--ollama-url", default=DEFAULT_URL)
    parser.add_argument("--hf", nargs="*", default=[], metavar="MODEL", help="HuggingFace model ids")
    parser.add_argument("--trials", type=int, default=1, help="trials per target (use 3+ for real models)")
    parser.add_argument("--seed", type=int, default=7, help="seed of the first trial")
    parser.add_argument("--temperature", type=float, default=0.7)
    parser.add_argument("--num-predict", type=int, default=200, help="max tokens per reply")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--sensitivity", choices=sorted(SENSITIVITY), default="standard")
    parser.add_argument("--judge-ollama", metavar="MODEL", help="also grade every probe with this judge model")
    parser.add_argument("--out", default=None, help="output directory")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    backends = []
    if args.scripted is not None:
        names = list(PROFILES) if not args.scripted or "all" in args.scripted else args.scripted
        unknown = [n for n in names if n not in PROFILES]
        if unknown:
            parser.error(f"unknown scripted profile(s) {unknown}; choose from {list(PROFILES)}")
        for name in names:
            backends.append(Backend(f"scripted-{name}", "scripted", lambda seed, n=name: ScriptedLLM(n)))

    needs_ollama = list(args.ollama) + ([args.judge_ollama] if args.judge_ollama else [])
    if needs_ollama:
        try:
            available = OllamaAdapter.available_models(args.ollama_url)
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(2)
        missing = [m for m in needs_ollama if not _pulled(m, available)]
        if missing:
            print("error: these models are not pulled yet:\n" + "\n".join(f"  ollama pull {m}" for m in missing),
                  file=sys.stderr)
            sys.exit(2)
    for model in args.ollama:
        backends.append(Backend(model, "ollama", lambda seed, m=model: OllamaAdapter(
            m, base_url=args.ollama_url, timeout=args.timeout, temperature=args.temperature,
            seed=seed, num_predict=args.num_predict)))
    for model in args.hf:
        backends.append(Backend(model, "huggingface", _hf_factory(model)))
    if not backends:
        parser.error("choose at least one target: --scripted, --ollama or --hf")

    judge = None
    if args.judge_ollama:
        judge = LLMJudge(OllamaAdapter(args.judge_ollama, base_url=args.ollama_url, timeout=args.timeout,
                                       temperature=0.0, seed=args.seed, num_predict=300))
    engine = RiskScoringEngine(deployment_sensitivity=args.sensitivity, judge=judge)
    out_dir = args.out or os.path.join("results", "run-" + datetime.now().strftime("%Y%m%d-%H%M%S"))

    run = run_benchmark(backends, trials=args.trials, base_seed=args.seed, engine=engine,
                        log=(lambda *_: None) if args.quiet else print)
    paths = write_outputs(run, out_dir)

    print("\nModel-level risk index (mean of direct, indirect and system-prompt attack scores):")
    for row in run["summary"]["model_index"]:
        app = ", ".join(f"{k} {v['risk']:.1f}" for k, v in row["app_leakage"].items())
        print(f"  {row['target']:<24} {row['model_risk_index']:5.1f} {row['severity']:<8}  app leakage: {app}")
    validation = run["summary"]["detector_validation"]
    if validation:
        v1, v0 = validation["scopes"]["all"]["v1"], validation["scopes"]["all"]["v0_baseline"]
        print(f"\nDetector vs ground truth (scripted targets, n={v1['n']}): precision {v1['precision']}, "
              f"recall {v1['recall']}, kappa {v1['kappa']}")
        if v0:
            print(f"  v0 substring baseline on its scope (n={v0['n']}): precision {v0['precision']}, "
                  f"recall {v0['recall']}, kappa {v0['kappa']}")
    print(f"\n{len(run['records'])} probes scored in {run['meta']['duration_s']}s. Reports: {paths['report.html']}")


if __name__ == "__main__":
    main()
