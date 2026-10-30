import json
import os

from sentinelai_harness.adapters.scripted_llm import ScriptedLLM
from sentinelai_harness.bench import Backend, ci95, run_benchmark, write_outputs


def _backends(*names):
    return [Backend(f"scripted-{n}", "scripted", lambda seed, n=n: ScriptedLLM(n)) for n in names]


def _quiet(*_):
    return None


def test_ci95_uses_student_t():
    assert ci95([5.0]) == 0.0
    assert abs(ci95([1.0, 2.0, 3.0]) - 4.303 / 3 ** 0.5) < 1e-6


def test_benchmark_end_to_end(tmp_path):
    run = run_benchmark(_backends("naive", "hardened"), trials=2, log=_quiet)
    probes_per_trial = 12 + 4 + 5 + 3 * 3
    assert len(run["records"]) == 2 * 2 * probes_per_trial

    index = {row["target"]: row for row in run["summary"]["model_index"]}
    assert index["scripted-naive"]["model_risk_index"] > 70 > index["scripted-hardened"]["model_risk_index"]
    hardened_app = index["scripted-hardened"]["app_leakage"]
    assert hardened_app["vulnerable"]["asr"] == 1.0 and hardened_app["patched"]["asr"] == 0.0
    # scripted targets are deterministic, so trials agree exactly
    assert all(a["risk_ci95"] == 0.0 for a in run["summary"]["attack_summary"])

    paths = write_outputs(run, str(tmp_path / "out"))
    assert all(os.path.getsize(p) > 0 for p in paths.values())
    with open(paths["summary.json"], encoding="utf-8") as f:
        assert json.load(f)["meta"]["trials"] == 2
    with open(paths["report.html"], encoding="utf-8") as f:
        page = f.read()
    assert "Scripted targets" in page and "<table" in page


def test_detector_validation_shows_the_v0_false_positives_are_fixed():
    scopes = run_benchmark(_backends("quoting"), log=_quiet)["summary"]["detector_validation"]["scopes"]
    assert scopes["prompt_injection"]["v0_baseline"]["fp"] > 0
    assert scopes["prompt_injection"]["v1"]["fp"] == 0
