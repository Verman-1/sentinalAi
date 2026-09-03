from sentinelai_harness.adapters.mock_adapter import MockAdapter
from sentinelai_harness.attacks.prompt_injection import PromptInjectionAttack, PAYLOADS


def test_detects_injection_on_vulnerable_model():
    adapter = MockAdapter(vulnerable_to_injection=True)
    result = PromptInjectionAttack().run(adapter)
    assert result.success is True
    assert len(result.transcript) == len(PAYLOADS)


def test_no_false_positive_on_hardened_model():
    adapter = MockAdapter(vulnerable_to_injection=False)
    result = PromptInjectionAttack().run(adapter)
    assert result.success is False
    assert "0/" in result.evidence
