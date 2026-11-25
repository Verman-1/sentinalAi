"""
Adapter for a locally-loaded HuggingFace Transformers model.

`transformers` and `torch` are imported lazily so the rest of the
harness (and its test suite) works without either installed.
"""

import time

from .base import ModelAdapter, ChatMessage


def resolve_device(device: str, cuda_available: bool) -> str:
    if device == "auto":
        return "cuda" if cuda_available else "cpu"
    if device.startswith("cuda") and not cuda_available:
        raise RuntimeError("CUDA requested but unavailable.")
    return device


def resolve_dtype_name(precision: str, device: str) -> str:
    if precision == "auto":
        return "float16" if device.startswith("cuda") else "float32"
    if precision not in ("float32", "float16", "bfloat16"):
        raise ValueError(f"Unknown precision: {precision}")
    return precision


class HuggingFaceAdapter(ModelAdapter):
    def __init__(self, model_name: str, device: str = "auto", precision: str = "auto",
                 max_new_tokens: int = 256, temperature: float = 0.7, top_p: float = 0.9,
                 do_sample: bool = True, revision: str | None = None):
        super().__init__(model_name)
        try:
            import torch
            import transformers
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as e:
            raise RuntimeError(
                "HuggingFaceAdapter requires 'transformers', 'torch' and 'accelerate'. "
                "pip install transformers torch accelerate"
            ) from e

        self._torch = torch
        self.device = resolve_device(device, torch.cuda.is_available())
        self.dtype_name = resolve_dtype_name(precision, self.device)
        dtype = getattr(torch, self.dtype_name)

        self.max_new_tokens = max_new_tokens
        self.temperature = temperature
        self.top_p = top_p
        self.do_sample = bool(do_sample and temperature > 0)  # temperature 0 => greedy
        self.seed: int | None = None
        self.last_latency_s = 0.0

        self.tokenizer = AutoTokenizer.from_pretrained(model_name, revision=revision)
        if self.tokenizer.pad_token_id is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        try:
            model = AutoModelForCausalLM.from_pretrained(model_name, revision=revision, dtype=dtype)
        except TypeError:  # older transformers only know torch_dtype
            model = AutoModelForCausalLM.from_pretrained(model_name, revision=revision, torch_dtype=dtype)
        self.model = model.to(self.device)
        self.model.eval()

        self._meta = {
            "model_id": model_name,
            "revision": revision,
            "resolved_commit": getattr(self.model.config, "_commit_hash", None),
            "n_params": sum(p.numel() for p in self.model.parameters()),
            "device": self.device,
            "dtype": self.dtype_name,
            "max_new_tokens": max_new_tokens,
            "temperature": temperature,
            "top_p": top_p,
            "do_sample": self.do_sample,
            "torch": torch.__version__,
            "transformers": transformers.__version__,
        }

    def set_seed(self, seed: int) -> None:
        """Seed python/numpy/torch(+CUDA) so a trial's sampling is repeatable."""
        from transformers import set_seed
        self.seed = seed
        set_seed(seed)

    def describe(self) -> dict:
        return dict(self._meta)

    def _build_prompt(self, messages: list[ChatMessage]) -> tuple[str, bool]:
        chat = [{"role": m.role, "content": m.content} for m in messages]
        if getattr(self.tokenizer, "chat_template", None):
            try:
                return self.tokenizer.apply_chat_template(
                    chat, tokenize=False, add_generation_prompt=True), True
            except Exception:
                # Some templates (e.g. Gemma 2) reject the "system" role:
                # fold it into the first user turn instead.
                sys_txt = "\n".join(m["content"] for m in chat if m["role"] == "system")
                rest = [m for m in chat if m["role"] != "system"]
                if sys_txt and rest and rest[0]["role"] == "user":
                    rest[0] = {"role": "user", "content": sys_txt + "\n\n" + rest[0]["content"]}
                return self.tokenizer.apply_chat_template(
                    rest, tokenize=False, add_generation_prompt=True), True
        return "\n".join(f"{m.role}: {m.content}" for m in messages) + "\nassistant:", False

    def _call(self, messages: list[ChatMessage]) -> str:
        prompt, templated = self._build_prompt(messages)
        # The chat template already inserts BOS where needed; don't add it twice.
        inputs = self.tokenizer(prompt, return_tensors="pt", add_special_tokens=not templated).to(self.device)

        gen_kwargs = {
            "max_new_tokens": self.max_new_tokens,
            "do_sample": self.do_sample,
            "pad_token_id": self.tokenizer.pad_token_id,
        }
        if self.do_sample:
            gen_kwargs.update(temperature=self.temperature, top_p=self.top_p)

        t0 = time.perf_counter()
        with self._torch.inference_mode():
            output_ids = self.model.generate(**inputs, **gen_kwargs)
        self.last_latency_s = time.perf_counter() - t0

        new_tokens = output_ids[0][inputs["input_ids"].shape[1]:]
        return self.tokenizer.decode(new_tokens, skip_special_tokens=True).strip()
