#!/usr/bin/env python3
"""refactor_order.py — reorder a go-firewall backend so it matches the Manager interface.

Ordering rules:
  1. Types and constants stay at the top (the preamble).
  2. The New<Type> constructor is placed immediately after the preamble.
  3. Remaining functions are ordered to match the `type Manager interface` list.
  4. Any helper must appear before the first function that calls it; dependencies are
     therefore hoisted in front of the exported method that needs them.

Doc comments attached to a function are moved together with the function.

Usage:
  scripts/refactor_order.py apf_linux.go                  # dry-run to stdout
  scripts/refactor_order.py apf_linux.go --apply          # rewrite in place
  scripts/refactor_order.py apf_linux.go --apply --gofmt  # rewrite and format
"""
import argparse
import os
import re
import subprocess
import sys
from collections import Counter

# Regex used to parse a column-0 `func` declaration line. Groups:
#   1: receiver variable (None for a plain function)
#   2: receiver type (None for a plain function)
#   3: function name
# A generic function's type-parameter list sits between the name and the
# signature, so it is skipped without capturing.
DECL_RE = re.compile(r"^func\s+(?:\((?:(\w+)\s+)?\*?(\w+)\)\s+)?([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*\(")


def split_blocks(text):
    """Split source into (preamble, [block_dict, ...]).

    A block starts at the function's doc comment and runs to the start of the
    next function's doc comment, so every line of the file lands in exactly one
    block and nothing can be dropped by the rewrite.

    A doc comment is the run of column-0 `//` lines immediately above the `func`
    line, which is what Go itself treats as the declaration's doc. Matching the
    comment's leading word against function names is deliberately avoided: a
    sentence that merely *starts* with another function's name (a wrapped line
    such as "// applyRuleFiles fanned out the axes before calling.") would
    otherwise be misread as the start of that function's doc comment.
    """
    lines = text.split("\n")
    func_lines = [i for i, line in enumerate(lines) if line.startswith("func ")]
    if not func_lines:
        return text, []

    # Parse every declaration and claim the doc comment directly above it.
    funcs = []
    for fl in func_lines:
        m = DECL_RE.match(lines[fl])
        if not m:
            die(f"could not parse declaration: {lines[fl]}")
        assert m
        doc_line = fl
        while doc_line > 0 and lines[doc_line - 1].startswith("//"):
            doc_line -= 1
        funcs.append(
            {
                "recv_var": m.group(1),
                "recv_type": m.group(2),
                "name": m.group(3),
                "doc_line": doc_line,
                "func_line": fl,
            }
        )

    # Everything above the first function's doc comment is the preamble.
    preamble_lines = lines[: funcs[0]["doc_line"]]
    preamble = "\n".join(preamble_lines)
    if preamble_lines:
        preamble += "\n"

    # Each block owns its doc comment, its body, and the blank separator that
    # follows, so blocks concatenate back into a well-formed file in any order.
    # Trailing blanks are normalized to a single separator line; the last block
    # keeps whatever follows it (there is no next doc comment to stop at).
    blocks = []
    for idx, f in enumerate(funcs):
        end = funcs[idx + 1]["doc_line"] if idx + 1 < len(funcs) else len(lines)
        block_lines = lines[f["doc_line"] : end]
        while block_lines and block_lines[-1] == "":
            block_lines.pop()
        blocks.append(
            {
                "recv_var": f["recv_var"],
                "recv_type": f["recv_type"],
                "name": f["name"],
                "text": "\n".join(block_lines) + "\n\n",
            }
        )

    return preamble, blocks


def parse_manager_interface(interface_path):
    """Return the method names of `type Manager interface` in order."""
    if not os.path.isfile(interface_path):
        die(f"interface file not found: {interface_path}")
    text = open(interface_path).read()
    m = re.search(r"type Manager interface \{(.*?)\n\}", text, re.DOTALL)
    if not m:
        die(f"type Manager interface not found in {interface_path}")
    assert m
    body = m.group(1)
    # Strip interface comments so they do not interfere with method detection.
    body = re.sub(r"(?m)^\s*//.*$", "", body)
    methods = re.findall(r"^\s+([A-Z]\w+)\s*\(", body, re.MULTILINE)
    return methods


def detect_backend_type_and_receiver(blocks):
    """Detect the dominant backend receiver type and variable name."""
    recv_counts = {}
    type_counts = {}
    for block in blocks:
        rv = block["recv_var"]
        rt = block["recv_type"]
        if rt:
            recv_counts[rv] = recv_counts.get(rv, 0) + 1
            type_counts[rt] = type_counts.get(rt, 0) + 1
    if not type_counts:
        die("could not detect a backend receiver type")
    backend_type = max(type_counts, key=lambda k: type_counts[k])
    receiver = max(recv_counts, key=lambda k: recv_counts[k]) if recv_counts else None
    return backend_type, receiver


def build_call_graph(blocks, receiver, backend_type):
    """Return a map from function name to the set of in-file functions it references.

    Both call shapes and bare method values count as references, since a
    dependency is anything that must already be declared for the reader to
    follow the code. The receiver-qualified regex therefore does not require a
    trailing "(": `f.removeRuleGroups` handed to a higher-order helper depends on
    it just as much as `f.removeRuleGroups(...)` would. Bare names still require
    the paren, because an unqualified name with no call syntax is far more often
    a prose mention inside a doc comment than a function value.
    """
    names = {block["name"] for block in blocks}
    graph = {name: set() for name in names}

    # Any variable holding the backend can reach its methods, not just the
    # dominant receiver: a constructor names its local something else (`ipt`),
    # and its calls would otherwise look like calls on an unrelated value.
    bt = re.escape(backend_type)
    alias_re = re.compile(rf"\b(\w+)\s*:?=\s*(?:&?{bt}\{{|new\(\s*{bt}\s*\))")

    for block in blocks:
        name = block["name"]
        text = block["text"]
        deps = graph[name]

        recvs = {receiver} if receiver else set()
        recvs.update(mm.group(1) for mm in alias_re.finditer(text))
        recvs.discard("")
        if recvs:
            method_re = re.compile(
                r"\b(?:" + "|".join(re.escape(r) for r in sorted(recvs)) + r")\.(\w+)\b"
            )
            for mm in method_re.finditer(text):
                called = mm.group(1)
                if called != name and called in names:
                    deps.add(called)

        # Plain function calls: name(...)
        # Exclude calls preceded by a dot, since those are method calls on some
        # other value and are already captured above for the backend receiver.
        for mm in re.finditer(r"(?<!\.)\b([A-Za-z_]\w*)\(", text):
            called = mm.group(1)
            if called != name and called in names:
                deps.add(called)

    return graph


def reorder(blocks, manager_order, constructor):
    """Return blocks in the required order."""
    backend_type, receiver = detect_backend_type_and_receiver(blocks)
    graph = build_call_graph(blocks, receiver, backend_type)
    name_to_block = {block["name"]: block for block in blocks}
    names = set(name_to_block.keys())

    if constructor not in names:
        die(f"constructor {constructor} not found in file")

    missing = [m for m in manager_order if m not in names]
    if missing:
        die(f"Manager interface methods missing from file: {missing}")

    order = []
    placed = set()
    active = set()

    def place(name):
        if name in placed or name in active:
            return
        if name not in name_to_block:
            return
        # active breaks a dependency cycle (mutual recursion, or a false edge
        # from a field that shares a function's name). One member of the cycle
        # necessarily ends up after a caller; Go does not mind, and the
        # alternative is unbounded recursion.
        active.add(name)
        for dep in sorted(graph.get(name, set())):
            place(dep)
        active.discard(name)
        order.append(name)
        placed.add(name)

    # 1. Constructor after preamble, before other functions.
    place(constructor)

    # 2. Manager interface methods in interface order.
    for method in manager_order:
        place(method)

    # 3. Any leftover functions (e.g. helper-only internals not reachable from
    #    the public surface) are appended in dependency order.
    for name in sorted(names):
        if name not in placed:
            place(name)

    return [name_to_block[name] for name in order]


def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(1)


def check_lossless(old_text, new_text):
    """Abort unless the rewrite is a pure permutation of the source.

    A reorder may only move lines, never add or drop them, so the multiset of
    non-blank lines must be identical on both sides. This is the backstop that
    catches a mis-attributed comment or a mis-sliced block before it reaches the
    file, since either shows up as a missing line rather than a Go syntax error.
    """
    before = Counter(l for l in old_text.split("\n") if l.strip())
    after = Counter(l for l in new_text.split("\n") if l.strip())
    lost = before - after
    gained = after - before
    if not lost and not gained:
        return
    for line in list(lost)[:20]:
        print(f"error: line dropped by reorder: {line}", file=sys.stderr)
    for line in list(gained)[:20]:
        print(f"error: line invented by reorder: {line}", file=sys.stderr)
    die("reorder is not lossless; the file was left unchanged")


def main():
    ap = argparse.ArgumentParser(
        description="Reorder a go-firewall backend to match the Manager interface and dependency order."
    )
    ap.add_argument("file", help="backend source file (e.g. apf_linux.go)")
    ap.add_argument(
        "--interface",
        default="firewall.go",
        help="file containing the Manager interface (default: firewall.go)",
    )
    ap.add_argument(
        "--constructor",
        help="constructor name override (default: New<Type> auto-detected)",
    )
    ap.add_argument("--apply", action="store_true", help="rewrite the file in place")
    ap.add_argument("--gofmt", action="store_true", help="run gofmt after rewriting")
    args = ap.parse_args()

    if not os.path.isfile(args.file):
        die(f"no such file: {args.file}")

    text = open(args.file).read()
    preamble, blocks = split_blocks(text)
    if not blocks:
        die("no functions found in file")

    backend_type, _ = detect_backend_type_and_receiver(blocks)
    constructor = args.constructor or ("New" + backend_type)

    manager_order = parse_manager_interface(args.interface)
    ordered = reorder(blocks, manager_order, constructor)
    new_text = preamble + "".join(block["text"] for block in ordered)
    new_text = new_text.rstrip("\n") + "\n"
    check_lossless(text, new_text)

    if not args.apply:
        print(new_text, end="")
        return

    open(args.file, "w").write(new_text)
    if args.gofmt:
        subprocess.run(["gofmt", "-w", args.file])
    print(f"reordered {args.file}")


if __name__ == "__main__":
    main()
