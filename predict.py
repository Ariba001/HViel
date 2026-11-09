"""
predict.py

Loads the trained Random Forest and runs it against a NEW binary
(one the model has never seen) to flag which functions look
vulnerable. This is the "automate reverse engineering + find
vulnerabilities" end of the pipeline: point it at a binary, Ghidra
does the reverse engineering, the model does the judging.

Usage:
    python predict.py model.joblib path/to/new_binary
"""

import sys

import joblib
import pandas as pd

from ghidra_extract import process_binary


def main(model_path, binary_path):
    bundle = joblib.load(model_path)
    clf = bundle["model"]
    feature_columns = bundle["feature_columns"]

    print(f"Reverse engineering {binary_path} with Ghidra...")
    rows = process_binary(binary_path)
    if not rows:
        print("No functions extracted (stripped binary? unsupported format?).")
        return

    df = pd.DataFrame(rows)
    X = df[feature_columns]

    predictions = clf.predict(X)
    probabilities = clf.predict_proba(X)[:, 1]  # P(vulnerable)

    df["predicted_label"] = predictions
    df["vulnerability_score"] = probabilities

    results = df.sort_values("vulnerability_score", ascending=False)

    print(f"\n{'Function':45s} {'Prediction':12s} {'Score':>8s}")
    print("-" * 68)
    for _, row in results.iterrows():
        verdict = "VULNERABLE" if row["predicted_label"] == 1 else "safe"
        print(f"{row['function_name']:45s} {verdict:12s} {row['vulnerability_score']:8.3f}")

    flagged = results[results["predicted_label"] == 1]
    print(f"\n{len(flagged)} / {len(results)} functions flagged as likely vulnerable.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python predict.py <model.joblib> <path_to_binary>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
