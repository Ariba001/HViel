"""
build_graphs.py

Two jobs:
  1. Walk a directory of compiled binaries, run
     ghidra_extract_graph.process_binary_to_graph on each, and cache the
     raw per-binary graph JSON (so you only pay the Ghidra cost once).
  2. Convert all those per-binary graphs into PyTorch Geometric `Data`
     objects and save them as a single dataset file train_gnn.py loads.

Usage:
    python build_graphs.py ./binaries_dir ./graph_cache_dir graphs.pt

Each binary becomes ONE separate graph (functions = nodes, calls =
edges) -- we do NOT merge binaries into one giant graph, since that
would create meaningless cross-binary edges and leak information
between train/test binaries.
"""

import json
import os
import sys

import torch
from torch_geometric.data import Data

from ghidra_extract_graph import GRAPH_FEATURE_COLUMNS, process_binary_to_graph


def find_binaries(root_dir):
    for dirpath, _dirnames, filenames in os.walk(root_dir):
        for name in filenames:
            if name.endswith((".py", ".csv", ".json", ".md", ".txt", ".pt")):
                continue
            yield os.path.join(dirpath, name)


def extract_and_cache(binaries_dir, cache_dir):
    os.makedirs(cache_dir, exist_ok=True)
    binaries = list(find_binaries(binaries_dir))
    print(f"Found {len(binaries)} candidate files under {binaries_dir}")

    graph_paths = []
    for i, path in enumerate(binaries, 1):
        cache_path = os.path.join(cache_dir, os.path.basename(path) + ".json")
        if os.path.exists(cache_path):
            print(f"[{i}/{len(binaries)}] cached: {path}")
            graph_paths.append(cache_path)
            continue
        print(f"[{i}/{len(binaries)}] extracting: {path}")
        try:
            graph = process_binary_to_graph(path)
        except Exception as exc:
            print(f"  [warn] could not analyze {path}: {exc}")
            continue
        with open(cache_path, "w") as f:
            json.dump(graph, f)
        graph_paths.append(cache_path)

    return graph_paths


def json_graph_to_pyg(graph: dict) -> Data:
    nodes = graph["nodes"]
    x = torch.tensor([n["features"] for n in nodes], dtype=torch.float)
    y = torch.tensor([n["label"] for n in nodes], dtype=torch.long)

    # train_mask marks nodes that actually have a Juliet bad/good label;
    # unlabeled helper/library functions still exist as graph structure
    # (so message passing can use them) but are excluded from the loss.
    mask = y != -1

    if graph["edges"]:
        edge_index = torch.tensor(graph["edges"], dtype=torch.long).t().contiguous()
        # Add reverse edges so information flows both caller->callee and
        # callee->caller during message passing.
        edge_index = torch.cat([edge_index, edge_index.flip(0)], dim=1)
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long)

    data = Data(x=x, edge_index=edge_index, y=y)
    data.label_mask = mask
    data.binary_name = graph["binary"]
    return data


def main(binaries_dir, cache_dir, out_file):
    graph_paths = extract_and_cache(binaries_dir, cache_dir)

    graphs = []
    for path in graph_paths:
        with open(path) as f:
            raw = json.load(f)
        if not raw["nodes"]:
            continue
        graphs.append(json_graph_to_pyg(raw))

    if not graphs:
        print("No graphs produced -- check binaries_dir and Ghidra setup.")
        return

    torch.save({"graphs": graphs, "feature_columns": GRAPH_FEATURE_COLUMNS}, out_file)

    total_nodes = sum(g.num_nodes for g in graphs)
    total_labeled = sum(int(g.label_mask.sum()) for g in graphs)
    total_vuln = sum(int((g.y[g.label_mask] == 1).sum()) for g in graphs)
    print(f"\nBuilt {len(graphs)} graphs, {total_nodes} total nodes")
    print(f"  labeled: {total_labeled} (vulnerable={total_vuln}, safe={total_labeled - total_vuln})")
    print(f"Saved to {out_file}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python build_graphs.py <binaries_dir> <graph_cache_dir> <out_graphs.pt>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2], sys.argv[3])
