"""
ghidra_extract_graph.py

Same per-function feature extraction as ghidra_extract.py, PLUS the
call graph (caller -> callee edges) for the binary, PLUS two graph
features (in_degree, out_degree) appended to each node's feature
vector. This is what feeds the GNN stage instead of the flat RF CSV.

Output: one JSON file per binary, e.g.

    {
      "binary": "CWE121_test1",
      "nodes": [
        {"id": 0, "function_name": "...", "features": [...], "label": 1},
        ...
      ],
      "edges": [[0, 3], [3, 7], ...]   # directed caller -> callee, by node id
    }

Usage (single binary, for sanity checking):
    python ghidra_extract_graph.py ./samples/CWE121_bad_binary out.json

Requires the same environment as ghidra_extract.py (pyhidra + local
Ghidra install + Java 17+).
"""

import json
import os
import sys

from ghidra_extract import (
    FEATURE_COLUMNS,
    _ensure_ghidra_started,
    _extract_cfg_stats,
    _extract_instruction_stats,
    label_from_name,
)

# Node feature order used everywhere downstream (build_graphs.py,
# train_gnn.py, predict_gnn.py) -- base structural features plus the
# two call-graph-derived features.
GRAPH_FEATURE_COLUMNS = FEATURE_COLUMNS + ["in_degree", "out_degree"]


def process_binary_to_graph(path: str) -> dict:
    """Extract one call graph (nodes + edges) for a single binary."""
    _ensure_ghidra_started()
    import pyhidra
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()

    with pyhidra.open_program(path) as flat_api:
        program = flat_api.getCurrentProgram()
        func_manager = program.getFunctionManager()

        funcs = [
            f for f in func_manager.getFunctions(True)
            if not f.isExternal() and not f.isThunk()
        ]

        # Stable id per function (by entry point address string).
        addr_to_id = {f.getEntryPoint().toString(): i for i, f in enumerate(funcs)}

        node_rows = []
        edges = []
        in_degree = [0] * len(funcs)
        out_degree = [0] * len(funcs)

        # First pass: base structural features + raw edges.
        func_edges_raw = []  # (caller_id, callee_entry_addr_string)
        for i, func in enumerate(funcs):
            try:
                row = {"function_name": func.getName()}
                row.update(_extract_instruction_stats(func, program))
                row.update(_extract_cfg_stats(func, program, monitor))
                stack_frame = func.getStackFrame()
                row["stack_size"] = stack_frame.getFrameSize() if stack_frame else 0
                row["num_params"] = func.getParameterCount()
                row["label"] = label_from_name(func.getName())
                node_rows.append(row)
            except Exception as exc:
                print(f"  [warn] skipped {func.getName()} in {path}: {exc}")
                node_rows.append(None)
                continue

            # Call edges: look at every CALL instruction's target.
            listing = program.getListing()
            for instr in listing.getInstructions(func.getBody(), True):
                if not instr.getMnemonicString().upper().startswith("CALL"):
                    continue
                for ref in instr.getReferencesFrom():
                    callee = func_manager.getFunctionAt(ref.getToAddress())
                    if callee is None or callee.isExternal():
                        continue
                    func_edges_raw.append((i, callee.getEntryPoint().toString()))

        # Second pass: resolve callee addresses to node ids, de-dup, count degree.
        seen = set()
        for caller_id, callee_addr in func_edges_raw:
            callee_id = addr_to_id.get(callee_addr)
            if callee_id is None or callee_id == caller_id:
                continue
            edge = (caller_id, callee_id)
            if edge in seen:
                continue
            seen.add(edge)
            edges.append(list(edge))
            out_degree[caller_id] += 1
            in_degree[callee_id] += 1

        nodes = []
        for i, row in enumerate(node_rows):
            if row is None:
                # Keep the node slot so edge ids stay valid, but give it
                # zeroed features and an unlabeled label.
                nodes.append({
                    "id": i,
                    "function_name": funcs[i].getName(),
                    "features": [0] * len(FEATURE_COLUMNS) + [in_degree[i], out_degree[i]],
                    "label": -1,
                })
                continue
            feature_vec = [row[col] for col in FEATURE_COLUMNS] + [in_degree[i], out_degree[i]]
            nodes.append({
                "id": i,
                "function_name": row["function_name"],
                "features": feature_vec,
                "label": row["label"],
            })

    return {
        "binary": os.path.basename(path),
        "nodes": nodes,
        "edges": edges,
    }


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python ghidra_extract_graph.py <path_to_binary> <out.json>")
        sys.exit(1)

    binary_path, out_path = sys.argv[1], sys.argv[2]
    print(f"Extracting call graph from {binary_path} ...")
    graph = process_binary_to_graph(binary_path)

    with open(out_path, "w") as f:
        json.dump(graph, f, indent=2)

    labeled = sum(1 for n in graph["nodes"] if n["label"] != -1)
    print(f"Extracted {len(graph['nodes'])} nodes, {len(graph['edges'])} call edges "
          f"({labeled} labeled). Wrote {out_path}")
