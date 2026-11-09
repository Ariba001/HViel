"""
predict_gnn.py

End-to-end on a brand-new, never-seen binary: Ghidra extracts the call
graph, the trained GraphSAGE model scores every function node.

Usage:
    python predict_gnn.py model_gnn.pt path/to/new_binary
"""

import sys

import torch
import torch.nn.functional as F

from ghidra_extract_graph import process_binary_to_graph
from build_graphs import json_graph_to_pyg
from train_gnn import GraphSAGE


def main(model_path, binary_path):
    bundle = torch.load(model_path, weights_only=False)
    feature_columns = bundle["feature_columns"]
    mean, std = bundle["feature_mean"], bundle["feature_std"]

    model = GraphSAGE(
        in_channels=len(feature_columns),
        hidden_channels=bundle["hidden_channels"],
        num_layers=bundle["num_layers"],
    )
    model.load_state_dict(bundle["model_state"])
    model.eval()

    print(f"Reverse engineering {binary_path} with Ghidra (call graph)...")
    raw_graph = process_binary_to_graph(binary_path)
    if not raw_graph["nodes"]:
        print("No functions extracted (stripped binary? unsupported format?).")
        return

    data = json_graph_to_pyg(raw_graph)
    data.x = (data.x - mean) / std

    with torch.no_grad():
        logits = model(data.x, data.edge_index)
        probs = F.softmax(logits, dim=1)[:, 1]
        preds = logits.argmax(dim=1)

    names = [n["function_name"] for n in raw_graph["nodes"]]
    order = torch.argsort(probs, descending=True)

    print(f"\n{'Function':45s} {'Prediction':12s} {'Score':>8s}")
    print("-" * 68)
    for idx in order.tolist():
        verdict = "VULNERABLE" if preds[idx].item() == 1 else "safe"
        print(f"{names[idx]:45s} {verdict:12s} {probs[idx].item():8.3f}")

    flagged = int((preds == 1).sum())
    print(f"\n{flagged} / {len(names)} functions flagged as likely vulnerable.")
    print(f"(Call graph used {data.edge_index.size(1)} directed edges, "
          f"including {raw_graph['edges'].__len__()} real call edges + reverse edges.)")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python predict_gnn.py <model_gnn.pt> <path_to_binary>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
