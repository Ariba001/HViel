"""
ghidra_extract.py

Opens ONE compiled binary in Ghidra (via pyhidra) and pulls out a
structural "feature vector" for every function in it -- no source
code needed.

Label trick (works for the NIST Juliet test suite your project already
uses): Juliet names its functions like

    CWE121_stack_based_buffer_overflow__bad()      -> vulnerable
    CWE121_stack_based_buffer_overflow__good()     -> patched / safe

So instead of hand-labeling anything, we just read the function name.
If you use your own binaries later, replace `label_from_name()` with
whatever labeling scheme fits your data (or leave everything unlabeled
and only use this script for the `predict.py` stage).

Requires:
    pip install pyhidra
    - A local Ghidra install (set GHIDRA_INSTALL_DIR env var, or pass
      install_dir=... to pyhidra.start())
    - Java 17+ on PATH (JAVA_HOME set)

Run directly on one binary to sanity-check the extractor:
    python ghidra_extract.py ./samples/CWE121_bad_binary
"""

import os
import sys

# NOTE: pyhidra.start() boots a JVM + Ghidra and requires GHIDRA_INSTALL_DIR
# to be set. We do NOT call it at import time, because other scripts
# (train_rf.py, build_graphs.py's downstream consumers, etc.) only need
# FEATURE_COLUMNS / label_from_name and should not pay that cost or
# require Ghidra to be installed. Ghidra is started lazily, only when
# process_binary() is actually called.
_ghidra_started = False


def _ensure_ghidra_started():
    global _ghidra_started
    if _ghidra_started:
        return
    import pyhidra
    pyhidra.start()
    _ghidra_started = True


# Calls into these are a strong structural signal of classic memory /
# injection bugs -- cheap substitute for real taint analysis.
DANGEROUS_CALLS = {
    "strcpy", "strcat", "sprintf", "gets", "scanf",
    "memcpy", "memmove", "system", "popen", "exec", "execve",
}

FEATURE_COLUMNS = [
    "num_instructions",
    "num_basic_blocks",
    "num_calls",
    "dangerous_call_count",
    "has_loop",
    "cyclomatic_complexity",
    "stack_size",
    "num_params",
    "num_mem_ops",
    "num_arith_ops",
]


def label_from_name(func_name: str) -> int:
    """Juliet-style auto-labeling. -1 means 'unlabeled, skip for training'."""
    name = func_name.lower()
    if "bad" in name:
        return 1
    if "good" in name:
        return 0
    return -1


def _extract_instruction_stats(func, program):
    listing = program.getListing()
    body = func.getBody()
    instructions = listing.getInstructions(body, True)

    num_instructions = 0
    num_calls = 0
    num_mem_ops = 0
    num_arith_ops = 0
    dangerous_call_count = 0

    func_manager = program.getFunctionManager()

    for instr in instructions:
        num_instructions += 1
        mnemonic = instr.getMnemonicString().upper()

        if mnemonic.startswith("CALL"):
            num_calls += 1
            for ref in instr.getReferencesFrom():
                called_func = func_manager.getFunctionAt(ref.getToAddress())
                if called_func and called_func.getName().lower() in DANGEROUS_CALLS:
                    dangerous_call_count += 1

        if mnemonic.startswith(("MOV", "LEA")) and "[" in instr.toString():
            num_mem_ops += 1

        if mnemonic.startswith(("ADD", "SUB", "MUL", "IMUL", "DIV", "IDIV")):
            num_arith_ops += 1

    return {
        "num_instructions": num_instructions,
        "num_calls": num_calls,
        "dangerous_call_count": dangerous_call_count,
        "num_mem_ops": num_mem_ops,
        "num_arith_ops": num_arith_ops,
    }


def _extract_cfg_stats(func, program, monitor):
    from ghidra.program.model.block import BasicBlockModel

    body = func.getBody()
    block_model = BasicBlockModel(program)
    blocks = list(block_model.getCodeBlocksContaining(body, monitor))

    num_blocks = len(blocks)
    num_edges = 0
    has_loop = False
    block_starts = {b.getFirstStartAddress() for b in blocks}

    for block in blocks:
        dest_iter = block.getDestinations(monitor)
        # Ghidra's CodeBlockReferenceIterator is a Java-style
        # hasNext()/next() iterator, not a Python iterable -- a plain
        # `for` loop over it silently fails, so walk it manually.
        while dest_iter.hasNext():
            dest_ref = dest_iter.next()
            num_edges += 1
            dest_block = dest_ref.getDestinationBlock()
            dest_start = dest_block.getFirstStartAddress()
            # a destination that is this block itself, or an earlier
            # block in program order, is a back-edge -> loop
            if dest_start in block_starts and dest_start.compareTo(block.getFirstStartAddress()) <= 0:
                has_loop = True

    cyclomatic = (num_edges - num_blocks + 2) if num_blocks else 0

    return {
        "num_basic_blocks": num_blocks,
        "has_loop": int(has_loop),
        "cyclomatic_complexity": cyclomatic,
    }


def extract_function_features(func, program, monitor):
    row = {"function_name": func.getName()}
    row.update(_extract_instruction_stats(func, program))
    row.update(_extract_cfg_stats(func, program, monitor))

    stack_frame = func.getStackFrame()
    row["stack_size"] = stack_frame.getFrameSize() if stack_frame else 0
    row["num_params"] = func.getParameterCount()
    row["label"] = label_from_name(func.getName())
    return row


def process_binary(path: str):
    """Returns a list of dict rows, one per non-thunk/non-external function."""
    _ensure_ghidra_started()
    import pyhidra
    from ghidra.util.task import ConsoleTaskMonitor

    rows = []
    monitor = ConsoleTaskMonitor()

    with pyhidra.open_program(path) as flat_api:
        program = flat_api.getCurrentProgram()
        func_manager = program.getFunctionManager()

        for func in func_manager.getFunctions(True):
            if func.isExternal() or func.isThunk():
                continue
            try:
                row = extract_function_features(func, program, monitor)
                row["binary"] = os.path.basename(path)
                rows.append(row)
            except Exception as exc:  # Ghidra API calls can be finicky per-function
                print(f"  [warn] skipped {func.getName()} in {path}: {exc}")

    return rows


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ghidra_extract.py <path_to_binary>")
        sys.exit(1)

    binary_path = sys.argv[1]
    print(f"Analyzing {binary_path} ...")
    results = process_binary(binary_path)

    print(f"\nExtracted {len(results)} functions:\n")
    for r in results:
        label_str = {1: "VULNERABLE", 0: "safe", -1: "unlabeled"}[r["label"]]
        print(f"  {r['function_name']:45s} label={label_str:10s} "
              f"instrs={r['num_instructions']:4d} cyclomatic={r['cyclomatic_complexity']:3d} "
              f"dangerous_calls={r['dangerous_call_count']}")
