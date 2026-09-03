from sentinelai_harness.adapters.mock_adapter import MockAdapter
from sentinelai_harness.attacks.context_leakage import ContextLeakageAttack, SECRET_NAME, SECRET_DESTINATION


def test_detects_leakage_on_vulnerable_backend():
    adapter = MockAdapter(vulnerable_to_leakage=True)
    result = ContextLeakageAttack().run(adapter)
    assert result.success is True
    assert SECRET_NAME in result.evidence or SECRET_DESTINATION in result.evidence


def test_no_false_positive_on_safe_backend():
    adapter = MockAdapter(vulnerable_to_leakage=False)
    result = ContextLeakageAttack().run(adapter)
    assert result.success is False


def test_reset_session_clears_client_history_not_backend():
    adapter = MockAdapter(vulnerable_to_leakage=True)
    adapter.send("my name is Test User")
    assert len(adapter.history) == 2  # user turn + assistant reply
    adapter.reset_session()
    assert adapter.history == []
    # backend memory (the simulated bug) survives the reset
    assert "name" in adapter._backend_memory
