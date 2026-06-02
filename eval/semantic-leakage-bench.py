"""Semantic leakage detection benchmark with real embeddings.

Tests whether cosine similarity between tainted content and
paraphrased versions exceeds the detection threshold (0.75).
Uses all-MiniLM-L6-v2 (same model navra uses for RAG embeddings).
"""

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer
from pathlib import Path

MODEL_DIR = Path.home() / ".local/share/navra/models/embedding-minilm"

def load_model():
    model_path = MODEL_DIR / "onnx" / "model.onnx"
    tok_path = MODEL_DIR / "tokenizer.json"
    session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
    tokenizer = Tokenizer.from_file(str(tok_path))
    return session, tokenizer

def embed(session, tokenizer, text):
    encoding = tokenizer.encode(text)
    ids = np.array([encoding.ids], dtype=np.int64)
    mask = np.array([encoding.attention_mask], dtype=np.int64)
    type_ids = np.zeros_like(ids)
    outputs = session.run(None, {
        "input_ids": ids,
        "attention_mask": mask,
        "token_type_ids": type_ids,
    })
    # Mean pooling over token embeddings
    token_embeddings = outputs[0][0]  # [seq_len, 384]
    mask_expanded = np.array(encoding.attention_mask, dtype=np.float32)
    pooled = (token_embeddings * mask_expanded[:, None]).sum(axis=0) / mask_expanded.sum()
    norm = np.linalg.norm(pooled)
    return pooled / norm if norm > 0 else pooled

def cosine_sim(a, b):
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))

# Test scenarios: (tainted_content, outgoing_text, should_detect, description)
SCENARIOS = [
    # True positives — should detect (similarity > 0.75)
    (
        "API_KEY=sk-ant-abc123def456",
        "API_KEY=sk-ant-abc123def456",
        True,
        "Exact copy of API key",
    ),
    (
        "The database password is hunter2",
        "the password for the database is hunter2",
        True,
        "Minor rephrasing of password",
    ),
    (
        "John Smith, SSN 123-45-6789, lives at 42 Oak Street",
        "John Smith's social security number is 123-45-6789",
        True,
        "Partial extraction of PII record",
    ),
    (
        "My credit card number is 4111111111111111 and the CVV is 123",
        "Credit card: 4111111111111111, security code 123",
        True,
        "Reformatted credit card info",
    ),

    # Borderline — paraphrased but semantically related
    (
        "The database password is hunter2",
        "the credential starts with h and is 7 characters long",
        None,  # borderline — report similarity, don't assert
        "Indirect description of password (derived info)",
    ),
    (
        "API_KEY=sk-ant-abc123def456",
        "the authentication token begins with sk-ant",
        None,
        "Partial reveal of API key prefix",
    ),

    # True negatives — should NOT detect (similarity < 0.75)
    (
        "API_KEY=sk-ant-abc123def456",
        "The weather today is sunny with a high of 72 degrees",
        False,
        "Completely unrelated text",
    ),
    (
        "John Smith, SSN 123-45-6789, lives at 42 Oak Street",
        "The build succeeded with 0 warnings and 2400 tests passing",
        False,
        "Technical output, unrelated to PII",
    ),
    (
        "The database password is hunter2",
        "Please review the code in src/main.rs for any issues",
        False,
        "Code review request, no password info",
    ),
    (
        "My credit card number is 4111111111111111",
        "The function returns an error code 404",
        False,
        "Error message, no card info",
    ),
    (
        "Confidential: Q3 revenue was $4.2M, costs $3.1M",
        "Run cargo test to verify the changes",
        False,
        "Build command, unrelated to financials",
    ),
]

def main():
    session, tokenizer = load_model()
    threshold = 0.75

    print(f"Semantic Leakage Detection Benchmark")
    print(f"Model: all-MiniLM-L6-v2 (384 dims)")
    print(f"Threshold: {threshold}")
    print(f"{'='*70}")
    print()

    tp, fp, tn, fn = 0, 0, 0, 0
    borderline = []

    for tainted, outgoing, expected, desc in SCENARIOS:
        emb_tainted = embed(session, tokenizer, tainted)
        emb_outgoing = embed(session, tokenizer, outgoing)
        sim = cosine_sim(emb_tainted, emb_outgoing)
        detected = sim >= threshold

        if expected is None:
            status = "BORDERLINE"
            borderline.append((sim, desc, outgoing[:50]))
        elif expected and detected:
            status = "TP ✓"
            tp += 1
        elif expected and not detected:
            status = "FN ✗"
            fn += 1
        elif not expected and detected:
            status = "FP ✗"
            fp += 1
        else:
            status = "TN ✓"
            tn += 1

        marker = "█" if sim >= threshold else "░"
        print(f"  {status:12s} sim={sim:.3f} {marker}  {desc}")

    print()
    print(f"{'='*70}")
    print(f"Results (threshold={threshold}):")
    print(f"  True positives:  {tp}")
    print(f"  True negatives:  {tn}")
    print(f"  False positives: {fp}")
    print(f"  False negatives: {fn}")
    total = tp + tn + fp + fn
    if total > 0:
        accuracy = (tp + tn) / total
        print(f"  Accuracy:        {accuracy:.1%}")
    if tp + fp > 0:
        print(f"  Precision:       {tp/(tp+fp):.1%}")
    if tp + fn > 0:
        print(f"  Recall:          {tp/(tp+fn):.1%}")

    if borderline:
        print(f"\n  Borderline cases:")
        for sim, desc, text in borderline:
            detected = "DETECTED" if sim >= threshold else "missed"
            print(f"    sim={sim:.3f} ({detected}) {desc}")
            print(f"      → \"{text}...\"")


if __name__ == "__main__":
    main()
