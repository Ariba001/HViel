# Mini-VIEL: Ghidra + Random Forest + GraphSAGE Binary Vulnerability Detector

A small, presentable slice of the full VIEL project: automatically
reverse-engineer compiled binaries with **Ghidra**, turn each function
into a feature vector, and classify functions as vulnerable or safe --
with no access to source code. Two models, same features, same labels:

- **Random Forest** -- each function judged in isolation.
- **GraphSAGE GNN** -- each function judged using its own features
  *plus* the features of functions it calls and is called by (the
  call graph), so it can catch vulnerable "thin wrapper" functions the
  RF can't see.

This repo already includes a **real, end-to-end run**:
`dataset.csv`, `graphs.pt`, `model.joblib` and `model_gnn.pt` were all
produced by actually compiling the C files in `samples/` with `gcc`
and running them through `ghidra_extract.py` / `ghidra_extract_graph.py`
with a real Ghidra install -- nothing here is simulated. `samples/`
contains 8 hand-written CWE bad/good pairs (stand-ins for the real
NIST Juliet Test Suite, which this repo doesn't bundle) compiled at
two optimization levels, giving 18 binaries / 248 functions / 68
labeled examples. That's a genuinely small dataset -- see "Honest
results from this repo" below before you trust the numbers too far.

## How it works (for your presentation)

1. **`ghidra_extract.py`** -- opens one binary in Ghidra (headlessly,
   via the `pyhidra` library) and, for every function, computes 10
   structural features:
   - instruction count, basic block count, cyclomatic complexity
   - whether the function contains a loop (back-edge in the CFG)
   - number of calls, and how many of those calls are to classically
     dangerous functions (`strcpy`, `gets`, `system`, `memcpy`, ...)
   - stack frame size, parameter count, memory-op count, arithmetic-op count

   It also auto-labels each function using the NIST Juliet Test Suite's
   own naming convention: a function named `..._bad()` is labeled
   vulnerable (1), `..._good()` is labeled safe (0). No manual
   annotation needed.

2. **`batch_extract.py`** -- runs step 1 across a whole folder of
   compiled Juliet binaries and writes one big `dataset.csv` (one row
   per function).

3. **`train_rf.py`** -- loads `dataset.csv`, splits 80/20 train/test,
   trains a `RandomForestClassifier`, and prints:
   - precision/recall/F1 for "vulnerable" vs "safe"
   - a confusion matrix
   - ROC-AUC
   - feature importances (which structural signals mattered most)
   Saves the trained model to `model.joblib`.

4. **`predict.py`** -- the "automated pipeline" end-to-end: give it a
   brand-new binary, it reverse-engineers it with Ghidra and scores
   every function's probability of being vulnerable, sorted highest
   first.

## GNN stage (GraphSAGE)

Adds call-graph awareness on top of the same per-function features.

5. **`ghidra_extract_graph.py`** -- same per-function feature
   extraction as step 1, but also walks every `CALL` instruction to
   build the binary's **call graph** (caller function -> callee
   function), and appends two graph-derived features to each node:
   `in_degree` (how many functions call it) and `out_degree` (how many
   functions it calls). Outputs one JSON graph per binary: nodes =
   functions, edges = calls.

6. **`build_graphs.py`** -- runs step 5 across a folder of binaries
   (caching each binary's extracted JSON so Ghidra only runs once per
   file), then converts every per-binary graph into a PyTorch Geometric
   `Data` object: node feature matrix `x`, directed edge list
   `edge_index` (call edges plus their reverse, so information flows
   both "I call something dangerous" and "something unsafe calls me"),
   node labels `y`, and a `label_mask` marking which nodes have a real
   Juliet bad/good label (helper functions without `bad`/`good` in
   their name stay in the graph as structure but are excluded from the
   training loss). Saves all graphs into one `graphs.pt`.

7. **`train_gnn.py`** -- trains a **3-layer GraphSAGE** node classifier.
   Critically, the train/val/test split is done **by binary** (whole
   graphs), not by individual function -- splitting by node would leak
   call-graph context between train and test. Z-score normalization
   statistics come from the train split only. Reports the same
   precision/recall/F1/confusion-matrix/ROC-AUC as the RF stage, so you
   can put the two side by side in your results slide.

8. **`predict_gnn.py`** -- same idea as `predict.py`: point it at a new
   binary, it extracts the call graph with Ghidra and scores every
   function node with the trained GraphSAGE model.

## Setup

```bash
# 1. Install Ghidra (https://ghidra-sre.org) and note its install path
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.x

# 2. Make sure Java 17+ is installed and JAVA_HOME is set

# 3. Python deps
pip install -r requirements.txt
```

## Running it

```bash
# Sanity-check the extractor on one binary
python ghidra_extract.py ./samples/CWE121_test_case

# Build a dataset from a folder of compiled Juliet binaries
python batch_extract.py ./juliet_binaries dataset.csv

# Train
python train_rf.py dataset.csv model.joblib

# Predict on a new, unseen binary
python predict.py model.joblib ./samples/some_new_binary
```

### GNN stage

```bash
# Extract call graphs for every binary + assemble the PyG dataset
python build_graphs.py ./juliet_binaries ./graph_cache graphs.pt

# Train GraphSAGE
python train_gnn.py graphs.pt model_gnn.pt

# Predict on a new, unseen binary (call-graph aware)
python predict_gnn.py model_gnn.pt ./samples/some_new_binary
```

`build_graphs.py` caches each binary's raw extraction as JSON under
`graph_cache/`, so re-running it after adding a few more binaries only
re-analyzes the new ones.

## Where to get test binaries

The NIST Juliet Test Suite (C/C++) is free and is exactly what your
full VIEL project already uses. Compile a subset of its test cases
with `gcc` (no special flags needed beyond `-g` if you want symbols)
and point `batch_extract.py` at the output folder.

## What to say in class

- **Problem**: can structural code shape alone (without source, without
  manual rules) predict which functions are buggy?
- **Pipeline**: Ghidra does the reverse engineering (disassembly, CFG
  recovery); a Random Forest does the classification.
- **Labels for free**: Juliet's `_bad`/`_good` naming convention gives
  ground truth without manual labeling effort.
- **Result to report**: whatever precision/recall/ROC-AUC you get on
  your held-out test set -- report it honestly, including which CWE
  categories the model struggles with (check `dataset.csv` grouped by
  CWE prefix in the binary name).
- **Honest limitation to mention** (this is what makes it a *good*
  presentation, not just a demo): a model trained only on synthetic
  Juliet bugs may not generalize to real-world code, because injected
  bugs don't always look like organically-written vulnerable code.
  That's a real, documented finding in the full VIEL project too.
- **RF vs GNN comparison**: report both models' test metrics side by
  side. If GraphSAGE wins, the likely story is that it's catching
  vulnerable wrapper/helper functions that look innocuous on their own
  but call something dangerous nearby in the call graph. If it doesn't
  beat RF by much, that's also a legitimate, reportable finding --
  the full VIEL project's own ablation found plain 3-layer SAGE beat a
  fancier attention-based GNN (GATv2), i.e. more graph machinery isn't
  automatically better; say what your data actually showed.

## Honest results from this repo

These are the real numbers produced by the artifacts already in this
repo (`dataset.csv`, `model.joblib`, `graphs.pt`, `model_gnn.pt`),
from 18 binaries / 248 functions / 68 labeled examples built from
`samples/`.

**Random Forest** (`train_rf.py dataset.csv model.joblib`):
- Accuracy: 86% (12/14 held-out functions)
- ROC-AUC: 0.92
- Top features: `num_instructions`, `cyclomatic_complexity`, `num_mem_ops`

**GraphSAGE GNN** (`train_gnn.py graphs.pt model_gnn.pt`):
- Accuracy: 67% (16/24 held-out functions)
- ROC-AUC: 0.71
- Lower than RF here, and that's expected: with only 18 graphs split
  11/3/4 train/val/test, the GNN doesn't have enough graphs to
  generalize well. This is not a fair RF-vs-GNN comparison -- it's
  what an 18-binary dataset supports. More binaries should close the
  gap.

**Qualitative finding (the one worth presenting):** on a hand-compiled
"unseen" binary where the vulnerable function is buried two wrapper
calls deep (`main -> level1_entry -> level2_helper -> core_copy_bad`),
RF scored the wrapper around the bad path and the wrapper around an
identical-looking safe path **exactly the same** (0.609 both) -- it
structurally can't distinguish them, since neither wrapper calls a
"dangerous" function directly. The GNN separated the true vulnerable
function far more sharply (1.000 vs RF's 0.746) by using call-graph
context, though with this little training data it also produced its
own false positive elsewhere. That trade-off -- GNN sees relational
signal RF can't, but needs more data to use it reliably -- is the
real takeaway of this project, and it mirrors a documented finding in
the full VIEL project itself (small datasets limit the Java/Python
pipelines there too).

## Extending back toward the full VIEL project

Once both models work, the natural next steps (all already scoped in
your full README) are: compare against the GATv2 attention variant,
wire this into the DevSecOps policy engine/SARIF reporter, and test
against real CVEs instead of only synthetic Juliet bugs.
