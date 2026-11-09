"""
train_gnn.py

Trains a GraphSAGE node classifier on the graphs built by
build_graphs.py. Each graph is one binary's call graph; each node is
a function; the task is node classification (vulnerable vs safe).

Split is done BY BINARY (by whole graph), not by individual node --
splitting by node would leak information, since functions from the
same binary that end up in both train and test sets share call-graph
context.

Usage:
    python train_gnn.py graphs.pt model_gnn.pt
"""

import sys

import torch
import torch.nn.functional as F
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
from torch_geometric.loader import DataLoader
from torch_geometric.nn import SAGEConv


class GraphSAGE(torch.nn.Module):
    """Plain 3-layer GraphSAGE. The full VIEL project found attention
    (GATv2) didn't beat this baseline -- vulnerability signal here is
    local (1-3 hops), so plain mean-aggregation SAGE is the right
    starting point rather than over-engineering."""

    def __init__(self, in_channels, hidden_channels=64, num_layers=3, dropout=0.3):
        super().__init__()
        self.convs = torch.nn.ModuleList()
        self.convs.append(SAGEConv(in_channels, hidden_channels))
        for _ in range(num_layers - 2):
            self.convs.append(SAGEConv(hidden_channels, hidden_channels))
        self.convs.append(SAGEConv(hidden_channels, hidden_channels))
        self.classifier = torch.nn.Linear(hidden_channels, 2)
        self.dropout = dropout

    def forward(self, x, edge_index):
        for conv in self.convs:
            x = conv(x, edge_index)
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)
        return self.classifier(x)


def normalize_features(graphs):
    """Z-score normalize node features using TRAIN graphs' statistics
    only, then apply to all graphs (avoids test-set leakage)."""
    all_x = torch.cat([g.x for g in graphs], dim=0)
    mean = all_x.mean(dim=0, keepdim=True)
    std = all_x.std(dim=0, keepdim=True).clamp_min(1e-6)
    return mean, std


def run_epoch(model, loader, optimizer, device, train: bool):
    model.train() if train else model.eval()
    total_loss, total_correct, total_count = 0.0, 0, 0
    all_labels, all_probs, all_preds = [], [], []

    for batch in loader:
        batch = batch.to(device)
        with torch.set_grad_enabled(train):
            logits = model(batch.x, batch.edge_index)
            mask = batch.label_mask
            if mask.sum() == 0:
                continue
            loss = F.cross_entropy(logits[mask], batch.y[mask])

            if train:
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()

        probs = F.softmax(logits[mask], dim=1)[:, 1]
        preds = logits[mask].argmax(dim=1)
        labels = batch.y[mask]

        total_loss += loss.item() * mask.sum().item()
        total_correct += (preds == labels).sum().item()
        total_count += mask.sum().item()
        all_labels.extend(labels.cpu().tolist())
        all_probs.extend(probs.detach().cpu().tolist())
        all_preds.extend(preds.cpu().tolist())

    avg_loss = total_loss / max(total_count, 1)
    acc = total_correct / max(total_count, 1)
    return avg_loss, acc, all_labels, all_preds, all_probs


def main(graphs_file, model_out, epochs=100, lr=0.01, hidden=64, num_layers=3):
    bundle = torch.load(graphs_file, weights_only=False)
    graphs = bundle["graphs"]
    feature_columns = bundle["feature_columns"]

    if len(graphs) < 4:
        print(f"Only {len(graphs)} graphs available -- GraphSAGE needs more binaries "
              f"to show its advantage over the per-function RF. Consider compiling "
              f"more Juliet test cases.")

    train_graphs, test_graphs = train_test_split(graphs, test_size=0.2, random_state=42)
    train_graphs, val_graphs = train_test_split(train_graphs, test_size=0.2, random_state=42)
    print(f"Split: {len(train_graphs)} train / {len(val_graphs)} val / {len(test_graphs)} test binaries")

    mean, std = normalize_features(train_graphs)
    for g in graphs:
        g.x = (g.x - mean) / std

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    train_loader = DataLoader(train_graphs, batch_size=8, shuffle=True)
    val_loader = DataLoader(val_graphs, batch_size=8)
    test_loader = DataLoader(test_graphs, batch_size=8)

    model = GraphSAGE(in_channels=len(feature_columns), hidden_channels=hidden,
                       num_layers=num_layers).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=5e-4)

    best_val_acc = 0.0
    best_state = None

    for epoch in range(1, epochs + 1):
        train_loss, train_acc, *_ = run_epoch(model, train_loader, optimizer, device, train=True)
        val_loss, val_acc, *_ = run_epoch(model, val_loader, optimizer, device, train=False)

        if val_acc >= best_val_acc:
            best_val_acc = val_acc
            best_state = {k: v.clone() for k, v in model.state_dict().items()}

        if epoch % 10 == 0 or epoch == 1:
            print(f"epoch {epoch:3d}  train_loss={train_loss:.4f} train_acc={train_acc:.4f}  "
                  f"val_loss={val_loss:.4f} val_acc={val_acc:.4f}")

    model.load_state_dict(best_state)
    test_loss, test_acc, labels, preds, probs = run_epoch(model, test_loader, optimizer, device, train=False)

    print(f"\n=== Test set performance (best val checkpoint, val_acc={best_val_acc:.4f}) ===")
    print(classification_report(labels, preds, target_names=["safe", "vulnerable"]))
    print("Confusion matrix:")
    print(confusion_matrix(labels, preds))
    try:
        print(f"ROC-AUC: {roc_auc_score(labels, probs):.4f}")
    except ValueError:
        pass

    torch.save({
        "model_state": model.state_dict(),
        "feature_columns": feature_columns,
        "hidden_channels": hidden,
        "num_layers": num_layers,
        "feature_mean": mean,
        "feature_std": std,
    }, model_out)
    print(f"\nSaved trained GNN to {model_out}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python train_gnn.py <graphs.pt> <model_out.pt>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
