"""Deterministic post-extraction passes: anchor verification, reference resolution, built-in properties."""
import os
import sys
from collections import deque
from . import ir as IRM


def check_anchors(ir, files, slack=2, log=sys.stderr):
    """Drop every fact whose ev.text is not a verbatim substring of the cited line (+-slack)."""
    dropped = []
    by_base = {}
    for f in files:  # LLMs sometimes cite a bare filename; accept it when unambiguous
        by_base.setdefault(os.path.basename(f), []).append(f)
    for key in IRM.LISTS:
        if key == "properties":
            continue
        keep = []
        for item in getattr(ir, key):
            ev = item.ev
            if ev and ev.file not in files and len(by_base.get(ev.file, [])) == 1:
                ev.file = by_base[ev.file][0]
            lines = files.get(ev.file) if ev else None
            ok = False
            if lines and isinstance(ev.line, int) and ev.text:
                for i in range(max(0, ev.line - 1 - slack), min(len(lines), ev.line + slack)):
                    if ev.text in lines[i]:
                        ok = True; break
            (keep if ok else dropped).append(item if ok else (key, item.id, ev))
        setattr(ir, key, keep)
    for key, id_, ev in dropped:
        print(f"[verify] dropped {key}/{id_}: bad anchor {ev}", file=log)
    return dropped


def resolve(ir, log=sys.stderr):
    """Drop dangling refs, normalise vars, downgrade non-code enforcement, add __start."""
    nodes = {n.id for n in ir.nodes}
    vars_ = {v.id: v for v in ir.vars}
    drop = lambda key, item, why: print(f"[verify] dropped {key}/{item.id}: {why}", file=log)
    ir.decisions = [d for d in ir.decisions if (d.node in nodes and d.var in vars_) or drop("decisions", d, "dangling ref")]
    ir.edges = [e for e in ir.edges if (e.src in nodes and e.dst in nodes) or drop("edges", e, "dangling ref")]
    edges = {e.id for e in ir.edges}
    ir.loops = [l for l in ir.loops if l.back_edge in edges or drop("loops", l, "dangling back_edge")]
    for d in ir.decisions:
        v = vars_[d.var]
        if v.type == "enum":
            v.values += [o for o in d.outcomes if o not in v.values]
    for v in ir.vars:
        if v.type == "enum":
            if v.init is not None and v.init not in v.values:
                v.values.append(v.init)
            if v.init is None and v.values:
                v.init = v.values[0]
        elif v.type == "bool":
            v.init = bool(v.init) if not isinstance(v.init, str) else v.init.lower() in ("true", "1", "yes")
        else:
            v.type = "int"
            try:
                v.init = int(v.init or 0)
            except (TypeError, ValueError):
                v.init = 0
    for item in ir.edges + ir.loops:
        if item.enforcement == "code" and not (item.ev and item.ev.file.endswith(IRM.CODE_EXTS)):
            print(f"[verify] {item.id}: enforcement code -> prose (anchor {item.ev.file if item.ev else None} is not code)", file=log)
            item.enforcement = "prose"
        elif item.enforcement != "code":
            item.enforcement = "prose"
    if "__start" not in nodes:
        back = {l.back_edge for l in ir.loops}
        incoming = {e.dst for e in ir.edges if e.id not in back}
        entry = [n.id for n in ir.nodes if n.id not in incoming] or \
                [n.id for n in ir.nodes if n.kind == "command"] or [n.id for n in ir.nodes]
        ir.nodes.insert(0, IRM.Node(id="__start", kind="command"))
        ir.edges = [IRM.Edge(id=f"__start_{t}", src="__start", dst=t) for t in entry] + ir.edges
    return ir


def derive_properties(ir, log=sys.stderr):
    """Built-in property classes. Extend by appending another block here."""
    props = []
    # gate bypass: a prose-only guard is not compiled into the edge; violating it is an unwanted path
    for e in ir.edges:
        if e.guard and e.enforcement == "prose":
            props.append(IRM.Property(id=f"gate_bypass_{e.id}", kind="never", args={"edge": e.id, "unless": e.guard}, ev=e.ev))
    # unbounded loop: prose bound -> bounded n; no bound -> bounded MAX_STEPS (documents the risk)
    for l in ir.loops:
        if l.enforcement == "prose":
            props.append(IRM.Property(id=f"unbounded_{l.id}", kind="bounded", args={"loop": l.id, "n": l.bound}, ev=l.ev))
    # unsafe side effect: dangerous node only after nearest upstream code-enforced gate, else guarded by incoming guards
    preds = {}
    for e in ir.edges:
        preds.setdefault(e.dst, []).append(e)
    code_gates = {e.src for e in ir.edges if e.guard and e.enforcement == "code"}
    for n in ir.nodes:
        if not IRM.DANGEROUS & set(n.effects):
            continue
        gate, seen, q = None, {n.id}, deque([n.id])
        while q and gate is None:
            for e in preds.get(q.popleft(), []):
                if e.src in code_gates:
                    gate = e.src; break
                if e.src not in seen:
                    seen.add(e.src); q.append(e.src)
        if gate:
            props.append(IRM.Property(id=f"unsafe_effect_{n.id}", kind="only_after", args={"node": n.id, "after": gate}, ev=n.ev))
        else:
            guards = [e.guard for e in preds.get(n.id, []) if e.guard]
            if guards:
                props.append(IRM.Property(id=f"unsafe_effect_{n.id}", kind="never",
                                          args={"node": n.id, "unless": " || ".join(f"({g})" for g in guards)}, ev=n.ev))
            else:
                print(f"[verify] warning: side-effect node {n.id} ({n.effects}) has no upstream gate or guard", file=log)
    have = {p.id for p in ir.properties}
    ir.properties += [p for p in props if p.id not in have]
    return ir
