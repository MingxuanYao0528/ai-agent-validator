"""Deterministic post-extraction passes: anchor verification, reference resolution, built-in properties."""
import os
import re
import sys
from collections import defaultdict
from . import ir as IRM

WORD = re.compile(r"[A-Za-z_][\w.\-]*")
EQ = re.compile(r"^\s*([A-Za-z_][\w.\-]*)\s*==\s*(.+?)\s*$")
CMP = re.compile(r"([A-Za-z_][\w.\-]*)\s*(?:==|!=|<=|>=|<|>)\s*(\"[^\"]*\"|[\w.\-]+)")


def check_anchors(ir, files, slack=2, log=sys.stderr):
    """Drop every fact whose ev.text is not a verbatim substring of the cited line (+-slack)."""
    dropped = []
    by_base = {}
    for f in files:  # LLMs sometimes cite a bare filename; accept it when unambiguous
        by_base.setdefault(os.path.basename(f), []).append(f)
    for key in IRM.LISTS:
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


def _words(text):
    return set(WORD.findall(text or "")) - {"visited", "true", "false"}


def _reads(expr):
    """{var: [compared values]} for every identifier in var position: left of a comparison, or bare (bool)."""
    out = defaultdict(list)
    for v, val in CMP.findall(expr or ""):
        out[v].append(val.strip('"'))
    for w in _words(CMP.sub(" ", re.sub(r"visited\([^)]*\)", " ", expr or ""))):
        out.setdefault(w, [])
    return out


def _merge_case_splits(ir, log):
    """Edges identical except for `var == V` guards over one var are one transition with a case label,
    not separate rules: fold them into one edge guarded by the disjunction."""
    groups = defaultdict(list)
    for e in ir.edges:
        groups[(e.src, e.dst, tuple(e.effect or ()), e.enforcement, e.guard_kind)].append(e)
    remap, drop = {}, set()
    for es in groups.values():
        es = [e for e in es if e.guard and EQ.match(e.guard)]  # only `var == V` guards take part
        parsed = [EQ.match(e.guard) for e in es]
        if len(es) < 2 or len({m[1] for m in parsed}) != 1:
            continue
        keep = es[0]
        keep.guard = " || ".join(f"{m[1]} == {m[2]}" for m in parsed)
        for e in es[1:]:
            remap[e.id] = keep.id; drop.add(e.id)
        print(f"[verify] folded case split {[e.id for e in es]} -> {keep.id}: {keep.guard}", file=log)
    ir.edges = [e for e in ir.edges if e.id not in drop]
    for l in ir.loops:
        l.back_edge = remap.get(l.back_edge, l.back_edge)
    for p in ir.properties:
        if p.args.get("edge") in remap:
            p.args["edge"] = remap[p.args["edge"]]


def resolve(ir, log=sys.stderr):
    """Drop dangling refs, normalise vars/edges, mark environment vars, fold case splits, add __start."""
    nodes = {n.id for n in ir.nodes}
    vars_ = {v.id: v for v in ir.vars}
    drop = lambda key, item, why: print(f"[verify] dropped {key}/{item.id}: {why}", file=log)
    ir.decisions = [d for d in ir.decisions if (d.node in nodes and d.var in vars_) or drop("decisions", d, "dangling ref")]
    ir.edges = [e for e in ir.edges if (e.src in nodes and e.dst in nodes) or drop("edges", e, "dangling ref")]
    for e in ir.edges:
        if e.guard_kind not in IRM.GUARD_KINDS:
            e.guard_kind = "only_if"
        if e.guard_kind == "advisory" and e.guard:
            e.guard = None  # a suggestion is not a rule: the transition stays nondeterministic
    for item in ir.edges + ir.loops:
        if item.enforcement == "code" and not (item.ev and item.ev.file.endswith(IRM.CODE_EXTS)):
            print(f"[verify] {item.id}: enforcement code -> prose (anchor {item.ev.file if item.ev else None} is not code)", file=log)
            item.enforcement = "prose"
        elif item.enforcement not in IRM.ENFORCEMENT:
            item.enforcement = "prose"
    _merge_case_splits(ir, log)
    edges = {e.id for e in ir.edges}
    ir.loops = [l for l in ir.loops if l.back_edge in edges or drop("loops", l, "dangling back_edge")]
    by_back = defaultdict(set)
    for l in ir.loops:
        by_back[l.back_edge].add(l.bound)
    for be, bounds in by_back.items():
        if len(bounds) > 1:
            print(f"[verify] warning: loop over edge {be} has conflicting bounds {sorted(map(str, bounds))} (source inconsistency)", file=log)
    loop_ids = {l.id for l in ir.loops}
    for p in ir.properties:
        a = p.args
        cond = (a.get("unless") or a.get("when") or "").strip().lower()
        if any(a.get(k) not in nodes for k in ("node", "after") if k in a) or ("edge" in a and a["edge"] not in edges) \
                or ("loop" in a and a["loop"] not in loop_ids):
            drop("properties", p, "dangling ref")
        elif cond in ("true", "false", "1", "0") or a.get("after") == a.get("node") \
                or cond == f"visited({a.get('node')})":
            drop("properties", p, "trivial or constant condition is not a rule")
        elif p.ev and p.ev.file.endswith(IRM.CODE_EXTS):
            drop("properties", p, "anchored in code: mechanically enforced, nothing to violate")
        else:
            continue
        a["__drop"] = True
    ir.properties = [p for p in ir.properties if "__drop" not in p.args]
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
    # a var that is read but never written by any decision or effect is an external fact: let the fuzzer choose it
    assigned = {d.var for d in ir.decisions} | {a.split("=")[0].strip().rstrip("+-") for e in ir.edges for a in (e.effect or [])}
    read = defaultdict(list)
    for x in [e.guard for e in ir.edges] + [p.args.get("unless") or p.args.get("when") for p in ir.properties]:
        for v, vals in _reads(x).items():
            read[v] += vals
    for w, vals in read.items():  # used but never declared: still an external fact, not a reason to drop the check
        if w not in vars_ and w not in nodes:
            num = vals and all(re.fullmatch(r"-?\d+", v) for v in vals)
            v = IRM.Var(id=w, type="int" if num else "enum" if vals else "bool", init=0 if num else None, values=[] if num else list(dict.fromkeys(vals)), env=True)
            ir.vars.append(v); vars_[w] = v
            print(f"[verify] {w}: used in a guard/property but never declared -> {v.type} environment input", file=log)
    for v in ir.vars:
        if v.id in read and v.id not in assigned and not v.env:
            v.env = True
            print(f"[verify] {v.id}: read but never assigned -> environment input (fuzzer-chosen)", file=log)
    if "__start" not in nodes:
        back = {l.back_edge for l in ir.loops}
        incoming = {e.dst for e in ir.edges if e.id not in back}
        entry = [n.id for n in ir.nodes if n.id not in incoming] or \
                [n.id for n in ir.nodes if n.kind == "command"] or [n.id for n in ir.nodes]
        ir.nodes.insert(0, IRM.Node(id="__start", kind="command"))
        ir.edges = [IRM.Edge(id=f"__start_{t}", src="__start", dst=t) for t in entry] + ir.edges
    return ir


def derive_properties(ir, log=sys.stderr):
    """Built-in property classes, each encoding a rule the MAS states. Extend by appending a block."""
    props = []
    code_pairs = {(e.src, e.dst) for e in ir.edges if e.enforcement == "code"}
    for e in ir.edges:
        if not e.guard or e.enforcement == "code":
            continue
        if (e.src, e.dst) in code_pairs:
            print(f"[verify] {e.id}: prose guard on a code-governed transition, no alarm derived", file=log)
            continue
        pre = "weak_gate_bypass" if e.enforcement == "weak" else "gate_bypass"
        if e.guard_kind in ("only_if", "iff"):   # taking the edge while its condition is false
            props.append(IRM.Property(id=f"{pre}_{e.id}", kind="never", args={"edge": e.id, "unless": e.guard}, ev=e.ev))
        if e.guard_kind in ("whenever", "iff"):  # not taking the edge while its condition is true
            props.append(IRM.Property(id=f"obligation_{e.id}", kind="must", args={"edge": e.id, "when": e.guard}, ev=e.ev))
    for l in ir.loops:
        if l.enforcement == "code":
            continue
        if l.bound is None:
            print(f"[verify] note: loop {l.id} states no bound (no alarm; nothing to violate)", file=log)
            continue
        props.append(IRM.Property(id=f"unbounded_{l.id}", kind="bounded", args={"loop": l.id, "n": l.bound}, ev=l.ev))
    preds = defaultdict(list)
    for e in ir.edges:
        preds[e.dst].append(e)
    for n in ir.nodes:
        for eff in n.forbidden_effects:
            props.append(IRM.Property(id=f"forbidden_effect_{n.id}_{eff}", kind="forbidden", args={"node": n.id, "effect": eff}, ev=n.ev))
        if IRM.DANGEROUS & set(n.effects) and not any(e.guard for e in preds[n.id]) and n.id != "__start":
            print(f"[verify] note: side-effect node {n.id} ({sorted(IRM.DANGEROUS & set(n.effects))}) has no guarded incoming edge", file=log)
    have = {p.id for p in ir.properties}
    ir.properties += [p for p in props if p.id not in have]
    return ir
