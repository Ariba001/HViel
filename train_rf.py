"""
train_rf.py

Trains a RandomForestClassifier on the feature CSV produced by
batch_extract.py, evaluates it on a held-out test split, and saves the
trained model to disk.

Usage:
    python train_rf.py dataset.csv model.joblib
"""

import sys

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split

from ghidra_extract import FEATURE_COLUMNS


def main(dataset_csv, model_out):
    df = pd.read_csv(dataset_csv)

    # Drop rows we couldn't label (anything that isn't a Juliet bad/good
    # function -- e.g. helper functions, main(), library code).
    df = df[df["label"].isin([0, 1])].copy()
    if df.empty:
        print("No labeled rows found. Check label_from_name() in ghidra_extract.py "
              "matches your binaries' function naming convention.")
        sys.exit(1)

    print(f"Loaded {len(df)} labeled functions "
          f"({(df['label'] == 1).sum()} vulnerable, {(df['label'] == 0).sum()} safe)")

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    print("\n=== Test set performance ===")
    print(classification_report(y_test, y_pred, target_names=["safe", "vulnerable"]))
    print("Confusion matrix (rows=actual, cols=predicted):")
    print(confusion_matrix(y_test, y_pred))
    try:
        print(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}")
    except ValueError:
        pass  # only one class present in a tiny test split

    print("\n=== Feature importances ===")
    importances = sorted(
        zip(FEATURE_COLUMNS, clf.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    )
    for name, importance in importances:
        print(f"  {name:25s} {importance:.4f}")

    joblib.dump({"model": clf, "feature_columns": FEATURE_COLUMNS}, model_out)
    print(f"\nSaved trained model to {model_out}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python train_rf.py <dataset.csv> <model_out.joblib>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
