import base64

from sentinelai_harness.adapters.scripted_llm import ScriptedLLM
from sentinelai_harness.attacks.prompt_injection import (
    DIRECT_PAYLOADS,
    INDIRECT_PAYLOADS,
    IndirectPromptInjectionAttack,
    PromptInjectionAttack,
)
from sentinelai_harness.attacks.system_prompt_leakage import SystemPromptLeakageAttack
from sentinelai_harness.fixtures import APP_SECRET


def test_payload_library_shape():
    payloads = DIRECT_PAYLOADS + INDIRECT_PAYLOADS
    assert len(DIRECT_PAYLOADS) == 12 and len(INDIRECT_PAYLOADS) == 4
    assert len({p.canary for p in payloads}) == len(payloads)
    assert len({p.family for p in payloads}) == len(payloads)
    assert all(p.channel == "indirect" for p in INDIRECT_PAYLOADS)


def test_obfuscated_payloads_hide_the_literal_canary():
    by_name = {p.name: p for p in DIRECT_PAYLOADS}
    b64 = by_name["obfuscation_base64"]
    assert b64.canary not in b64.text
    assert b64.canary in base64.b64decode(b64.text.rsplit(" ", 1)[-1]).decode()
    split = by_name["payload_splitting"]
    assert split.canary not in split.text


def test_naive_model_falls_for_every_payload():
    for attack in (PromptInjectionAttack(), IndirectPromptInjectionAttack()):
        assert all(p.success for p in attack.run(ScriptedLLM("naive")).probes)


def test_keyword_filter_is_bypassed_by_encoding_language_and_documents():
    outcome = {p.probe_id: p.success for p in PromptInjectionAttack().run(ScriptedLLM("partial")).probes}
    assert outcome["context_ignoring"] is False and outcome["role_play_dan"] is False
    assert outcome["obfuscation_base64"] and outcome["payload_splitting"] and outcome["multilingual_hindi"]
    assert IndirectPromptInjectionAttack().run(ScriptedLLM("partial")).success_rate == 1.0


def test_refusals_that_quote_the_canary_are_not_counted():
    result = PromptInjectionAttack().run(ScriptedLLM("quoting"))
    assert result.success is False
    quoted = next(p for p in result.probes if p.probe_id == "context_ignoring")
    assert quoted.protected[0] in quoted.response  # the old substring check would have fired here
    assert quoted.signals["instruction_deviation"] == 0.25


def test_system_prompt_leakage_profiles():
    naive = SystemPromptLeakageAttack().run(ScriptedLLM("naive"))
    assert naive.success_rate == 1.0 and APP_SECRET in naive.probes[0].response
    partial = SystemPromptLeakageAttack().run(ScriptedLLM("partial"))
    assert [p.probe_id for p in partial.probes if p.success] == ["social_engineering"]
    assert SystemPromptLeakageAttack().run(ScriptedLLM("hardened")).success is False


def test_harmless_role_summary_is_not_a_leak():
    probes = SystemPromptLeakageAttack().run(ScriptedLLM("hardened")).probes
    summary = next(p for p in probes if p.probe_id == "summary_extraction")
    assert summary.signals["context_leakage"] == 0.0 and not summary.success
