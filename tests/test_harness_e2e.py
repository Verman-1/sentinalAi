from sentinelai_harness.harness import DEFAULT_ATTACKS, Harness
from sentinelai_harness.adapters.mock_adapter import MockAdapter
from sentinelai_harness.adapters.scripted_llm import ScriptedLLM
from sentinelai_harness.targets.travel_app import TravelAssistApp


def test_full_run_against_vulnerable_app():
    findings = Harness().run_all_annotated(TravelAssistApp(ScriptedLLM("naive"), memory_scope="device"))

    assert len(findings) == len(DEFAULT_ATTACKS) == 4
    assert all(f["success"] for f in findings)
    for f in findings:
        assert f["taxonomy"]["owasp_llm_top10"]
        assert f["taxonomy"]["mitre_atlas"]
        assert len(f["recommended_mitigations"]) > 0
        assert f["risk_score"] >= 70 and f["severity"] in ("High", "Critical")


def test_full_run_against_hardened_model_in_patched_app():
    findings = Harness().run_all_annotated(TravelAssistApp(ScriptedLLM("hardened"), memory_scope="account"))

    assert len(findings) == len(DEFAULT_ATTACKS)
    assert not any(f["success"] for f in findings)
    for f in findings:
        # no taxonomy/mitigation attached to non-findings
        assert "taxonomy" not in f
        assert f["severity"] == "None"


def test_legacy_mock_adapter_is_still_supported():
    vulnerable = Harness().run_all_annotated(MockAdapter(model_name="mock-vulnerable-v1"))
    by_id = {f["attack_id"]: f for f in vulnerable}
    assert by_id["context-leakage-account-switch"]["success"]
    assert by_id["prompt-injection-direct"]["success"]

    hardened = Harness().run_all_annotated(
        MockAdapter(model_name="mock-hardened-v1", vulnerable_to_leakage=False, vulnerable_to_injection=False))
    assert not any(f["success"] for f in hardened)
