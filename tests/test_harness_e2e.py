from sentinelai_harness.harness import Harness
from sentinelai_harness.adapters.mock_adapter import MockAdapter


def test_full_run_against_vulnerable_mock():
    harness = Harness()
    adapter = MockAdapter(model_name="mock-vulnerable-v1", vulnerable_to_leakage=True, vulnerable_to_injection=True)
    findings = harness.run_all_annotated(adapter)

    assert len(findings) == 2
    assert all(f["success"] for f in findings)
    for f in findings:
        assert "taxonomy" in f
        assert f["taxonomy"]["owasp_llm_top10"]
        assert f["taxonomy"]["mitre_atlas"]
        assert len(f["recommended_mitigations"]) > 0


def test_full_run_against_hardened_mock():
    harness = Harness()
    adapter = MockAdapter(model_name="mock-hardened-v1", vulnerable_to_leakage=False, vulnerable_to_injection=False)
    findings = harness.run_all_annotated(adapter)

    assert len(findings) == 2
    assert not any(f["success"] for f in findings)
    # no taxonomy/mitigation attached to non-findings
    for f in findings:
        assert "taxonomy" not in f
