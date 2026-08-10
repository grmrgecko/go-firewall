#!/usr/bin/env python3
"""refactor_backend.py — normalize function placement/naming in a go-firewall backend.

The library's convention, modeled on the APF refactor:

  * A function used by more than one backend stays a package-level global.
  * A function used only by this backend lives under the backend struct as a method.
  * A method's name never repeats the backend token (the receiver already namespaces
    it): apfNeedsHook -> (*APF).needsHook, isAPFConfRule -> (*APF).isConfRule.
  * Visibility is preserved: an exported helper stays exported, an unexported one
    stays unexported. Exported methods are the surface "people working with the
    backend directly out of the manager interface" call.
  * The New<Type> constructor stays a global.

The script parses the backend file, classifies every function, and (with --apply)
rewrites the backend file, its _test.go, and bare-name mentions in sibling files.
Default is a dry run that prints the plan. Naming is heuristic — review the plan,
and pass --rename a=b,c=d to override any proposed name.

Usage:
  scripts/refactor_backend.py csf_linux.go                 # dry-run plan
  scripts/refactor_backend.py csf_linux.go --prefix csf    # override token(s)
  scripts/refactor_backend.py csf_linux.go --apply
  scripts/refactor_backend.py csf_linux.go --apply --rename fooBar=baz
"""
import argparse
import os
import re
import subprocess
import sys

# Go initialisms handled when lowercasing a leading word so an acronym stays intact
# (NATFamilies -> natFamilies, IPv6Unavailable -> ipv6Unavailable, not nATFamilies).
INITIALISMS = [
    "ICMPV6", "ICMPV4", "HTTPS", "IPV4", "IPV6", "ICMP", "HTTP", "SCTP",
    "NAT", "TCP", "UDP", "DNS", "URL", "URI", "API", "TLS", "SSH", "ACL",
    "ID", "IP", "WFP", "UFW", "CSF", "APF", "NFT", "PF",
]

# Group 1: receiver variable (optional — a method may use an anonymous receiver
# like `func (*IPTables) IgnoreLine(...)`). Group 2: receiver type. Group 3: name.
# Group 4: type-parameter list of a generic function, which Go forbids on methods.
FUNC_RE = re.compile(
    r"^func\s+(?:\((?:(\w+)\s+)?\*?(\w+)\)\s+)?([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*\(",
    re.MULTILINE,
)


def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(1)


def split_blocks(text):
    """Split gofmt'd Go source into (preamble, [(header_line_idx, [lines])...]).

    A top-level declaration starts with `func ` in column 0 and ends at the next
    column-0 `func ` (gofmt guarantees the layout). Only func blocks are returned;
    everything before the first func is the preamble.
    """
    lines = text.split("\n")
    starts = [i for i, l in enumerate(lines) if l.startswith("func ")]
    if not starts:
        return lines, []
    preamble = lines[: starts[0]]
    blocks = []
    for n, s in enumerate(starts):
        e = starts[n + 1] if n + 1 < len(starts) else len(lines)
        blocks.append((s, lines[s:e]))
    return preamble, blocks


def results(header):
    """Return the result section of a declaration header, empty when it has none.

    The parameter list is skipped by balancing parentheses, since a parameter may
    itself be a func type whose own parens would fool a plain regex.
    """
    start = header.find("(")
    if start < 0:
        return ""
    depth = 0
    for i in range(start, len(header)):
        if header[i] == "(":
            depth += 1
        elif header[i] == ")":
            depth -= 1
            if depth == 0:
                return header[i + 1:].rstrip().rstrip("{").strip()
    return ""


def to_unexported(name):
    """Lowercase the leading word of an identifier, keeping acronyms whole."""
    if not name or name[0].islower():
        return name
    up = name.upper()
    for init in sorted(INITIALISMS, key=len, reverse=True):
        if up.startswith(init) and len(name) >= len(init):
            return name[: len(init)].lower() + name[len(init):]
    i = 0
    while i < len(name) and name[i].isupper():
        i += 1
    if i <= 1:
        return name[0].lower() + name[1:]
    if i < len(name):  # uppercase run followed by lowercase: last upper starts a word
        return name[: i - 1].lower() + name[i - 1:]
    return name.lower()


def strip_tokens(name, tokens):
    """Remove each backend token from an identifier as a camelCase/acronym segment."""
    for tok in tokens:
        low, up, cap = tok.lower(), tok.upper(), tok.capitalize()
        if name.startswith(low) and (len(name) == len(low) or name[len(low)].isupper()):
            name = name[len(low):]
        name = name.replace(up, "")
        name = re.sub(cap + r"(?=[A-Z]|$)", "", name)
    return name


def target_name(old, exported, tokens):
    """Proposed identifier: token stripped, original visibility preserved."""
    stripped = strip_tokens(old, tokens) or old
    if exported:
        return stripped[0].upper() + stripped[1:]
    return to_unexported(stripped)


def main():
    ap = argparse.ArgumentParser(description="Normalize a go-firewall backend's function placement/naming.")
    ap.add_argument("file", help="backend source file (e.g. csf_linux.go)")
    ap.add_argument("--type", help="receiver struct type (auto-detected by default)")
    ap.add_argument("--recv", help="receiver variable name for converted globals (auto-detected)")
    ap.add_argument("--prefix", help="comma-separated backend token(s) to strip (default: lowercased type)")
    ap.add_argument("--rename", default="", help="comma-separated old=new overrides for proposed names")
    ap.add_argument("--via", default="",
                    help="comma-separated Type=expr paths from a non-backend receiver to the backend (e.g. nftDecoder=d.f)")
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry-run plan only)")
    ap.add_argument("--no-tests", action="store_true", help="do not touch the _test.go file")
    ap.add_argument("--no-comments", action="store_true", help="do not update bare-name mentions in sibling files")
    args = ap.parse_args()

    path = args.file
    if not os.path.isfile(path):
        die("no such file: " + path)
    pkgdir = os.path.dirname(os.path.abspath(path)) or "."
    text = open(path).read()

    # Detect the receiver type and its dominant receiver-variable name.
    recv_types, recv_vars = {}, {}
    for m in FUNC_RE.finditer(text):
        rv, rt = m.group(1), m.group(2)
        if rt:
            recv_types[rt] = recv_types.get(rt, 0) + 1
            recv_vars.setdefault(rt, {})
            recv_vars[rt][rv] = recv_vars[rt].get(rv, 0) + 1
    typ = args.type or (max(recv_types, key=recv_types.get) if recv_types else None)
    if not typ:
        die("could not detect a receiver type; pass --type")
    recv = args.recv or (max(recv_vars.get(typ, {"f": 1}), key=recv_vars.get(typ, {"f": 1}).get))
    tokens = [t for t in (args.prefix.split(",") if args.prefix else [typ.lower()]) if t]
    overrides = dict(p.split("=", 1) for p in args.rename.split(",") if "=" in p)

    # Enumerate this file's top-level declarations.
    preamble, blocks = split_blocks(text)
    decls = []  # (name, is_method, recv_var, header_idx)
    for hidx, blk in blocks:
        m = FUNC_RE.match(blk[0])
        if not m:
            continue
        decls.append({"name": m.group(3), "method": bool(m.group(2)),
                      "recv": m.group(1), "rtype": m.group(2),
                      "generic": bool(m.group(4)), "hidx": hidx})
    names = {d["name"] for d in decls}

    # A constructor for any type declared in this file stays global, matching
    # newHookScript/newAtomicFile: the type it builds, not the backend, owns it.
    # A constructor is a new-prefixed global returning a locally declared type,
    # which also catches a name that drops the backend token (newSetReader for
    # *nftSetReader).
    local_types = set(re.findall(r"(?m)^type\s+(\w+)\b", text))
    ctors = set()
    for hidx, blk in blocks:
        m = FUNC_RE.match(blk[0])
        if not m or m.group(2) or not m.group(3).startswith(("new", "New")):
            continue
        if any(re.search(r"\b" + re.escape(t) + r"\b", results(blk[0])) for t in local_types):
            ctors.add(m.group(3))

    # Methods on a type other than the backend reach a converted global only
    # through an explicit path (--via nftDecoder=d.f); without one they cannot
    # call it at all, so anything they use is held back as a global.
    via = dict(p.split("=", 1) for p in args.via.split(",") if "=" in p)
    stranded = {d["name"] for d in decls
                if d["method"] and d["rtype"] != typ and d["rtype"] not in via}

    # Which globals are shared? A global referenced by any sibling .go file other than
    # this file and its own _test.go must stay global.
    base = os.path.basename(path)
    testbase = base[:-3] + "_test.go"
    shared = set()
    siblings = [f for f in os.listdir(pkgdir)
                if f.endswith(".go") and f not in (base, testbase)]
    for f in siblings:
        raw = open(os.path.join(pkgdir, f)).read()
        # Strip line comments so a bare mention in another file's comment does not
        # masquerade as real cross-backend usage.
        body = "\n".join(l.split("//", 1)[0] for l in raw.split("\n"))
        for d in decls:
            if not d["method"] and re.search(r"\b" + re.escape(d["name"]) + r"\b", body):
                shared.add(d["name"])

    # Reference graph within this file: which declared names each block's body uses.
    body_refs = {}
    for hidx, blk in blocks:
        m = FUNC_RE.match(blk[0])
        who = m.group(3)
        used = set()
        for line in blk[1:]:
            code = line.split("//", 1)[0]
            for n in names:
                if re.search(r"\b" + re.escape(n) + r"\(", code):
                    used.add(n)
        body_refs[who] = used
    method_names = {d["name"] for d in decls if d["method"]}

    # Decide each function's fate.
    #   keep-global : constructor / shared / generic / (guarded) called by a staying global
    #   to-method   : backend-only global -> method
    #   rename      : method whose name carries the token
    convert = set()  # globals that will become methods
    for d in decls:
        if d["method"]:
            continue
        # Go has no type-parameterized methods, so a generic helper stays global.
        if d["name"] == "New" + typ or d["name"] in shared or d["generic"] or d["name"] in ctors:
            continue
        convert.add(d["name"])
    # A converted global cannot be called from a context with no receiver in scope:
    # a function that stays a plain global, a method with an anonymous receiver, or
    # a method on another type with no --via path. Demote such names back to global
    # until the set is stable.
    anon_methods = {d["name"] for d in decls if d["method"] and not d["recv"]}
    changed = True
    while changed:
        changed = False
        no_recv = (shared | {"New" + typ} | ctors | anon_methods | stranded
                   | {d["name"] for d in decls if not d["method"] and d["name"] not in convert})
        for g in list(convert):
            callers = [w for w, u in body_refs.items() if g in u]
            if any(c in no_recv for c in callers):
                convert.discard(g)
                changed = True

    plan = []  # (old, new, action)
    for d in decls:
        old = d["name"]
        if not d["method"]:
            if old in convert:
                new = overrides.get(old) or target_name(old, old[0].isupper(), tokens)
                plan.append((old, new, "global->method"))
            else:
                if old == "New" + typ or old in ctors:
                    why = "constructor"
                elif old in shared:
                    why = "shared"
                elif d["generic"]:
                    why = "generic"
                else:
                    why = "kept-global"
                plan.append((old, old, why))
            continue
        # Existing method: strip the token if present, preserve visibility.
        stripped = strip_tokens(old, tokens)
        if stripped and stripped != old:
            new = overrides.get(old) or target_name(old, old[0].isupper(), tokens)
            plan.append((old, new, "method-rename"))
        else:
            plan.append((old, overrides.get(old, old), "method-ok"))

    # Report.
    rename_map = {o: n for o, n, a in plan if n != o}
    print(f"# {base}: type=*{typ} recv={recv} tokens={tokens}")
    edits = [p for p in plan if p[2] in ("global->method", "method-rename")]
    print(f"# {len(edits)} change(s), {len(rename_map)} of them renames; "
          f"{len(shared)} shared global(s) left in place\n")
    width = max((len(o) for o, _, _ in plan), default=1)
    for old, new, action in plan:
        arrow = f"-> {new}" if new != old else ""
        note = ""
        if action == "global->method":
            note = f"  (now {recv}.{new})"
        print(f"  [{action:14}] {old:<{width}} {arrow}{note}")
    # Collisions.
    seen = {}
    for old, new, action in plan:
        if action in ("global->method", "method-rename"):
            seen.setdefault(new, []).append(old)
    for new, olds in seen.items():
        if len(olds) > 1 or new in (method_names - set(rename_map)):
            print(f"  ! WARNING: name collision on {new}: {olds}")

    if not args.apply:
        print("\n(dry run — re-run with --apply to write changes)")
        return

    apply_source(path, text, plan, typ, recv, blocks, convert, rename_map, via)
    if not args.no_tests:
        tpath = os.path.join(pkgdir, testbase)
        if os.path.isfile(tpath):
            apply_test(tpath, plan, typ, convert, rename_map, recv)
    if not args.no_comments:
        for f in siblings:
            apply_comments(os.path.join(pkgdir, f), rename_map)

    changed_files = [path]
    if not args.no_tests and os.path.isfile(os.path.join(pkgdir, testbase)):
        changed_files.append(os.path.join(pkgdir, testbase))
    subprocess.run(["gofmt", "-w", *changed_files])
    print(f"\napplied. gofmt'd {len(changed_files)} file(s). Now run: go vet ./... && go test ./...")


def rewrite_body(lines, block_recv, convert_new, method_new):
    """Rewrite one block's body lines: global-call sites gain a receiver, method
    renames swap the identifier, and bare comment mentions are renamed."""
    out = []
    for line in lines:
        # Longest-first so no old name is a prefix of another.
        for old in sorted(convert_new, key=len, reverse=True):
            new = convert_new[old]
            if block_recv:
                line = re.sub(r"\b" + re.escape(old) + r"\(", f"{block_recv}.{new}(", line)
            line = re.sub(r"\b" + re.escape(old) + r"\b(?!\()", new, line)
        for old in sorted(method_new, key=len, reverse=True):
            line = re.sub(r"\b" + re.escape(old) + r"\b", method_new[old], line)
        out.append(line)
    return out


def apply_source(path, text, plan, typ, recv, blocks, convert, rename_map, via=None):
    convert_new = {o: n for o, n, a in plan if a == "global->method"}
    method_new = {o: n for o, n, a in plan if a == "method-rename"}
    preamble, blocks = split_blocks(text)
    out = list(preamble)
    for hidx, blk in blocks:
        m = FUNC_RE.match(blk[0])
        name = m.group(3)
        header, body = blk[0], blk[1:]
        if name in convert_new:
            # Global declaration becomes a method; body callers get the receiver.
            new = convert_new[name]
            header = re.sub(r"^func\s+" + re.escape(name) + r"\(",
                            f"func ({recv} *{typ}) {new}(", header)
            block_recv = recv
        elif m.group(2):  # existing method
            # A method on another type reaches the backend only through its --via
            # path, so converted calls are qualified with that instead.
            block_recv = m.group(1) if m.group(2) == typ else (via or {}).get(m.group(2))
            if name in method_new:
                header = re.sub(r"\b" + re.escape(name) + r"\b", method_new[name], header, count=1)
        else:  # staying global function
            block_recv = None
        out.append(header)
        out.extend(rewrite_body(body, block_recv, convert_new, method_new))
    open(path, "w").write("\n".join(out))


def apply_test(path, plan, typ, convert, rename_map, recv):
    """Rewrite the backend's _test.go. Method renames are plain swaps; a global that
    became a method needs an instance at each call site — reuse a local one or inject
    `fw := new(Type)` at the top of the test function."""
    convert_new = {o: n for o, n, a in plan if a == "global->method"}
    method_new = {o: n for o, n, a in plan if a == "method-rename"}
    text = open(path).read()
    preamble, blocks = split_blocks(text)

    # Preferred instance-variable name: the one tests already use most, else "fw".
    inst_counts = {}
    for pat in (r"(\w+)\s*:=\s*new\(" + typ + r"\)", r"(\w+)\s*:=\s*&" + typ + r"\{"):
        for mm in re.finditer(pat, text):
            inst_counts[mm.group(1)] = inst_counts.get(mm.group(1), 0) + 1
    default_inst = max(inst_counts, key=inst_counts.get) if inst_counts else "fw"

    out = list(preamble)
    for hidx, blk in blocks:
        header, body = blk[0], list(blk[1:])
        text_body = "\n".join(body)
        needs = any(re.search(r"\b" + re.escape(o) + r"\(", text_body) for o in convert_new)
        # An instance already local to this test function?
        inst = None
        for pat in (r"(\w+)\s*:=\s*new\(" + typ + r"\)", r"(\w+)\s*:=\s*&" + typ + r"\{",
                    r"var\s+(\w+)\s+\*?" + typ + r"\b"):
            mm = re.search(pat, text_body)
            if mm:
                inst = mm.group(1)
                break
        inject = needs and inst is None
        if inject:
            inst = default_inst
        recv_for_calls = inst  # in tests, "receiver" is the instance var
        new_body = []
        for line in body:
            for old in sorted(convert_new, key=len, reverse=True):
                new = convert_new[old]
                if recv_for_calls:
                    line = re.sub(r"\b" + re.escape(old) + r"\(", f"{recv_for_calls}.{new}(", line)
                line = re.sub(r"\b" + re.escape(old) + r"\b(?!\()", new, line)
            for old in sorted(method_new, key=len, reverse=True):
                line = re.sub(r"\b" + re.escape(old) + r"\b", method_new[old], line)
            new_body.append(line)
        out.append(header)
        if inject:
            out.append(f"\t{inst} := new({typ})")
        out.extend(new_body)
    open(path, "w").write("\n".join(out))


def apply_comments(path, rename_map):
    """Update bare-name mentions of renamed identifiers in a sibling file's comments.
    Only touches lines that are comments and only replaces the exact old identifier."""
    if not rename_map:
        return
    lines = open(path).read().split("\n")
    changed = False
    for i, line in enumerate(lines):
        if "//" not in line:
            continue
        code, _, comment = line.partition("//")
        new_comment = comment
        for old in sorted(rename_map, key=len, reverse=True):
            new_comment = re.sub(r"\b" + re.escape(old) + r"\b", rename_map[old], new_comment)
        if new_comment != comment:
            lines[i] = code + "//" + new_comment
            changed = True
    if changed:
        open(path, "w").write("\n".join(lines))


if __name__ == "__main__":
    main()
