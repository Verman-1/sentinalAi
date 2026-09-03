"""
Adapter for a locally-loaded HuggingFace Transformers model.

Heavier than the Ollama adapter (needs the model weights and, ideally,
a GPU) but useful when you want to test a model that isn't packaged
for Ollama, or need direct access to logits/embeddings later for the
risk-scoring engine.

`transformers` and `torch` are imported lazily so the rest of the
harness (and its test suite, via MockAdapter) works without either
installed.
"""

from .base import ModelAdapter, ChatMessage


class HuggingFaceAdapter(ModelAdapter):
    def __init__(self, model_name: str, device: str = "cpu", max_new_tokens: int = 256):
        super().__init__(model_name)
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            import torch
        except ImportError as e:
            raise RuntimeError(
                "HuggingFaceAdapter requires 'transformers' and 'torch'. "
                "pip install transformers torch"
            ) from e

        self._torch = torch
        self.max_new_tokens = max_new_tokens
        self.device = device
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForCausalLM.from_pretrained(model_name).to(device)

    def _call(self, messages: list[ChatMessage]) -> str:
        chat = [{"role": m.role, "content": m.content} for m in messages]
        if hasattr(self.tokenizer, "apply_chat_template"):
            prompt = self.tokenizer.apply_chat_template(chat, tokenize=False, add_generation_prompt=True)
        else:
            prompt = "\n".join(f"{m.role}: {m.content}" for m in messages) + "\nassistant:"

        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.device)
        with self._torch.no_grad():
            output_ids = self.model.generate(
                **inputs,
                max_new_tokens=self.max_new_tokens,
                do_sample=False,
                pad_token_id=self.tokenizer.eos_token_id,
            )
        new_tokens = output_ids[0][inputs["input_ids"].shape[1]:]
        return self.tokenizer.decode(new_tokens, skip_special_tokens=True).strip()
