"""CPU BGE embeddings using the ONNX export; no generative model or PyTorch."""

import hashlib
import json
from pathlib import Path

import httpx
import numpy as np

REPOSITORY = "Xenova/bge-small-en-v1.5"
REVISION = "ea104da"


class TextEmbedding:
    def __init__(self, model_name, cache_dir):
        if model_name != "BAAI/bge-small-en-v1.5":
            raise ValueError("This deployment supports the audited BGE small v1.5 embedding model")
        import onnxruntime as ort
        from tokenizers import Tokenizer

        cache = Path(cache_dir) / "bge-small-en-v1.5-onnx"
        cache.mkdir(parents=True, exist_ok=True)
        for filename in ["tokenizer.json", "onnx/model_quantized.onnx"]:
            target = cache / Path(filename).name
            if not target.exists():
                partial = target.with_suffix(target.suffix + ".partial")
                with httpx.Client(timeout=180, follow_redirects=True) as client:
                    with client.stream(
                        "GET", f"https://huggingface.co/{REPOSITORY}/resolve/{REVISION}/{filename}"
                    ) as response:
                        response.raise_for_status()
                        with partial.open("wb") as out:
                            for chunk in response.iter_bytes():
                                out.write(chunk)
                partial.replace(target)
        (cache / "manifest.json").write_text(
            json.dumps(
                {
                    "repository": REPOSITORY,
                    "revision": REVISION,
                    "files": {
                        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in cache.glob("*")
                        if p.suffix in {".onnx", ".json"} and p.name != "manifest.json"
                    },
                },
                indent=2,
            )
        )
        self.tokenizer = Tokenizer.from_file(str(cache / "tokenizer.json"))
        self.tokenizer.enable_truncation(max_length=512)
        self.tokenizer.enable_padding(pad_id=0, pad_token="[PAD]")
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 2
        self.session = ort.InferenceSession(
            str(cache / "model_quantized.onnx"), sess_options=opts, providers=["CPUExecutionProvider"]
        )

    def embed(self, texts, batch_size=16):
        texts = list(texts)
        for start in range(0, len(texts), batch_size):
            encoded = self.tokenizer.encode_batch(texts[start : start + batch_size])
            feeds = {
                "input_ids": np.array([e.ids for e in encoded], dtype=np.int64),
                "attention_mask": np.array([e.attention_mask for e in encoded], dtype=np.int64),
                "token_type_ids": np.array([e.type_ids for e in encoded], dtype=np.int64),
            }
            names = {i.name for i in self.session.get_inputs()}
            output = self.session.run(None, {k: v for k, v in feeds.items() if k in names})[0]
            pooled = output[:, 0] if output.ndim == 3 else output
            normalized = pooled / np.maximum(np.linalg.norm(pooled, axis=1, keepdims=True), 1e-9)
            yield from normalized

    def query_embed(self, query):
        return self.embed(["Represent this sentence for searching relevant passages: " + query])
