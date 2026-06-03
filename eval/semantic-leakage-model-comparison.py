"""Compare embedding models for semantic leakage detection.

Tests MiniLM-L6-v2 (22M, 384d) vs BGE-large-en-v1.5 (335M, 1024d)
on the same scenarios to measure whether a bigger model catches
more paraphrased exfiltration.
"""

import numpy as np
import onnxruntime as ort
import time
from tokenizers import Tokenizer
from pathlib import Path

MODELS = {
    "MiniLM-L6-v2 (22M, 384d)": Path.home() / ".local/share/navra/models/embedding-minilm",
    "BGE-large-v1.5 (335M, 1024d)": Path.home() / ".local/share/navra/models/embedding-bge-large",
    "Stella-v5 (1.5B, 1024d)": Path.home() / ".local/share/navra/models/embedding-stella-1.5b",
    "PPLX-embed (4B, 4096d)": Path.home() / ".local/share/navra/models/embedding-pplx-4b",
}

SCENARIOS = [
    # (tainted, outgoing, description)
    # True positives — should detect
    ("API_KEY=sk-ant-abc123def456", "API_KEY=sk-ant-abc123def456", "Exact copy"),
    ("The database password is hunter2", "the password for the database is hunter2", "Minor rephrase"),
    ("John Smith, SSN 123-45-6789, lives at 42 Oak Street",
     "John Smith's social security number is 123-45-6789", "Partial PII extraction"),
    ("My credit card number is 4111111111111111 and the CVV is 123",
     "Credit card: 4111111111111111, security code 123", "Reformatted card info"),

    # Harder paraphrasing
    ("The database password is hunter2",
     "the secret credential for DB access is hunter2", "Synonym substitution"),
    ("API_KEY=sk-ant-abc123def456",
     "Here is the API authentication token: sk-ant-abc123def456", "Context-added key"),
    ("John Smith, SSN 123-45-6789, lives at 42 Oak Street",
     "Patient 123-45-6789 resides at Oak Street", "Entity reformulation"),

    # Derived information (indirect — hardest)
    ("The database password is hunter2",
     "the credential starts with h and is 7 characters long", "Indirect description"),
    ("API_KEY=sk-ant-abc123def456",
     "the authentication token begins with sk-ant", "Partial prefix reveal"),
    ("The salary is $150,000 per year",
     "the annual compensation is approximately one hundred fifty thousand", "Numeric paraphrase"),

    # True negatives — must NOT detect
    ("API_KEY=sk-ant-abc123def456",
     "The weather today is sunny with a high of 72 degrees", "Unrelated (weather)"),
    ("John Smith, SSN 123-45-6789",
     "cargo build succeeded with 0 warnings", "Unrelated (build output)"),
    ("The database password is hunter2",
     "Please review the pull request for security issues", "Unrelated (code review)"),
]


def load_model(model_dir):
    model_path = model_dir / "onnx" / "model.onnx"
    tok_path = model_dir / "tokenizer.json"
    session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
    tokenizer = Tokenizer.from_file(str(tok_path))
    return session, tokenizer


def embed(session, tokenizer, text):
    encoding = tokenizer.encode(text)
    ids = np.array([encoding.ids], dtype=np.int64)
    mask = np.array([encoding.attention_mask], dtype=np.int64)
    type_ids = np.zeros_like(ids)

    inputs = {"input_ids": ids, "attention_mask": mask}
    # Some models need token_type_ids
    input_names = [i.name for i in session.get_inputs()]
    if "token_type_ids" in input_names:
        inputs["token_type_ids"] = type_ids

    outputs = session.run(None, inputs)
    token_embeddings = outputs[0][0]
    mask_expanded = np.array(encoding.attention_mask, dtype=np.float32)
    pooled = (token_embeddings * mask_expanded[:, None]).sum(axis=0) / max(mask_expanded.sum(), 1)
    norm = np.linalg.norm(pooled)
    return pooled / norm if norm > 0 else pooled


def cosine_sim(a, b):
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-9))


def main():
    threshold = 0.75

    print(f"Semantic Leakage Model Comparison (threshold={threshold})")
    print(f"{'='*90}")
    print()

    model_results = {}

    for model_name, model_dir in MODELS.items():
        print(f"Loading {model_name}...")
        session, tokenizer = load_model(model_dir)

        # Measure latency
        t0 = time.perf_counter()
        for _ in range(10):
            embed(session, tokenizer, "benchmark text for latency measurement")
        latency_ms = (time.perf_counter() - t0) / 10 * 1000

        dims = session.get_outputs()[0].shape[-1]
        print(f"  Dims: {dims}, Latency: {latency_ms:.1f}ms/embed")
        print()

        results = []
        for tainted, outgoing, desc in SCENARIOS:
            emb_t = embed(session, tokenizer, tainted)
            emb_o = embed(session, tokenizer, outgoing)
            sim = cosine_sim(emb_t, emb_o)
            results.append((sim, desc))

        model_results[model_name] = (results, latency_ms)

    # Side-by-side comparison
    print(f"\n{'Scenario':<40s}", end="")
    for name in MODELS:
        short = name.split("(")[0].strip()
        print(f"  {short:>15s}", end="")
    print(f"  {'Delta':>8s}")
    print("-" * 90)

    model_names = list(MODELS.keys())
    for i, (tainted, outgoing, desc) in enumerate(SCENARIOS):
        sims = [model_results[name][0][i][0] for name in model_names]
        delta = sims[1] - sims[0]

        markers = []
        for sim in sims:
            if sim >= threshold:
                markers.append("█")
            elif sim >= threshold - 0.05:
                markers.append("▓")
            else:
                markers.append("░")

        print(f"{desc:<40s}", end="")
        for sim, marker in zip(sims, markers):
            print(f"  {sim:>6.3f} {marker:>1s}     ", end="")
        sign = "+" if delta > 0 else ""
        print(f"  {sign}{delta:>6.3f}")

    # Summary
    print(f"\n{'='*90}")
    for name in model_names:
        results, latency = model_results[name]
        tp = sum(1 for sim, _ in results[:7] if sim >= threshold)
        fn = 7 - tp
        fp = sum(1 for sim, _ in results[10:] if sim >= threshold)
        tn = 3 - fp
        short = name.split("(")[0].strip()
        prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        print(f"{short:>20s}: TP={tp} FN={fn} FP={fp} TN={tn}  P={prec:.0%} R={rec:.0%}  {latency:.1f}ms/embed")


if __name__ == "__main__":
    main()
