"""
batch_extract.py

Walks a directory of compiled binaries, runs ghidra_extract.py's
per-binary extractor on each one, and writes everything into a single
dataset.csv that train_rf.py can consume.

Usage:
    python batch_extract.py ./binaries_dir dataset.csv

Expected input layout (any layout works, the labels come from the
*function names* inside the binary, not the folder structure):

    binaries_dir/
        CWE121_a.out
        CWE122_a.out
        CWE78_a.out
        ...

Juliet test cases are usually built as one binary per test case,
containing both the _bad and _good function in the same file -- that's
fine, this script just extracts every function it finds.
"""

import csv
import os
import sys

from ghidra_extract import FEATURE_COLUMNS, process_binary


def find_binaries(root_dir):
    for dirpath, _dirnames, filenames in os.walk(root_dir):
        for name in filenames:
            full_path = os.path.join(dirpath, name)
            # Skip obvious non-binaries; adjust this filter to your dataset.
            if name.endswith((".py", ".csv", ".md", ".txt", ".json")):
                continue
            yield full_path


def main(binaries_dir, out_csv):
    all_rows = []
    binaries = list(find_binaries(binaries_dir))
    print(f"Found {len(binaries)} candidate files under {binaries_dir}")

    for i, path in enumerate(binaries, 1):
        print(f"[{i}/{len(binaries)}] {path}")
        try:
            rows = process_binary(path)
        except Exception as exc:
            print(f"  [warn] could not analyze {path} (not a supported binary?): {exc}")
            continue
        all_rows.extend(rows)

    if not all_rows:
        print("No functions extracted -- check that binaries_dir points at real binaries.")
        return

    fieldnames = ["binary", "function_name"] + FEATURE_COLUMNS + ["label"]
    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in all_rows:
            writer.writerow({k: row.get(k) for k in fieldnames})

    labeled = sum(1 for r in all_rows if r["label"] != -1)
    vulnerable = sum(1 for r in all_rows if r["label"] == 1)
    print(f"\nWrote {len(all_rows)} function rows to {out_csv}")
    print(f"  labeled: {labeled}  (vulnerable={vulnerable}, safe={labeled - vulnerable})")
    print(f"  unlabeled (skipped by trainer): {len(all_rows) - labeled}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python batch_extract.py <binaries_dir> <out_dataset.csv>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
