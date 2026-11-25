import os

import pytest

from sentinelai_harness import bench
from sentinelai_harness.adapters.huggingface_adapter import resolve_device, resolve_dtype_name


def test_auto_device():
    assert resolve_device("auto", True) == "cuda"
    assert resolve_device("auto", False) == "cpu"
    assert resolve_device("cpu", True) == "cpu"


def test_explicit_cuda_unavailable_raises():
    with pytest.raises(RuntimeError):
        resolve_device("cuda", False)


def test_dtype_selection():
    assert resolve_dtype_name("auto", "cuda") == "float16"
    assert resolve_dtype_name("auto", "cpu") == "float32"
    assert resolve_dtype_name("bfloat16", "cuda") == "bfloat16"
    with pytest.raises(ValueError):
        resolve_dtype_name("int3", "cpu")


def test_factory_loads_once_resets_and_seeds(monkeypatch):
    import sentinelai_harness.adapters.huggingface_adapter as hf
    calls = {"init": [], "seeds": [], "resets": 0}

    class Fake:
        def __init__(self, name, **kw):
            calls["init"].append((name, kw))
        def hard_reset(self):
            calls["resets"] += 1
        def set_seed(self, s):
            calls["seeds"].append(s)
        def describe(self):
            return {"model_id": "fake"}

    monkeypatch.setattr(hf, "HuggingFaceAdapter", Fake)
    make = bench._hf_factory("fake/model", {"device": "cpu"})
    assert make.info() == {}                      # nothing loaded yet
    make(7); make(8); make(8)
    assert len(calls["init"]) == 1                # weights loaded once
    assert calls["init"][0] == ("fake/model", {"device": "cpu"})
    assert calls["seeds"] == [7, 8, 8]
    assert calls["resets"] == 3
    assert make.info() == {"hf": {"model_id": "fake"}}


@pytest.mark.skipif(not os.getenv("RUN_HF_TESTS"), reason="downloads a ~1GB model")
def test_same_seed_reproduces_different_seed_varies():
    from sentinelai_harness.adapters.base import ChatMessage
    from sentinelai_harness.adapters.huggingface_adapter import HuggingFaceAdapter
    a = HuggingFaceAdapter("Qwen/Qwen2.5-0.5B-Instruct", max_new_tokens=40, temperature=1.0)
    msgs = [ChatMessage("user", "Write one sentence about the sea.")]
    a.set_seed(7); x = a._call(msgs)
    a.set_seed(7); y = a._call(msgs)
    a.set_seed(8); z = a._call(msgs)
    assert x == y
    assert x != z  # overwhelmingly likely at temperature 1.0
