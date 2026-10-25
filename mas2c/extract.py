"""General LLM-driven frontend: any MAS repo -> IR. No framework-specific parsing."""
import json
import os
import re
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from . import ir as IRM
from .llm import chat, parse_json

EXTS = (".md", ".txt", ".json", ".yaml", ".yml", ".sh", ".py", ".toml", ".ts", ".js")
SKIP_DIRS = {".git", "node_modules", "__pycache__"}
MAX_FILE = 200_000
CHUNK_CHARS = 30_000

SYSTEM = """You extract a multi-agent system (MAS) into a formal IR for program analysis (fuzzing).
Output ONLY one JSON object with keys vars, nodes, decisions, edges, loops, properties. Schema:
""" + IRM.SCHEMA + """

Framework-agnostic definitions:
- node: an actor or executable unit: an agent/LLM role (agent), a procedure/skill/prompt template an agent invokes in-context (skill), a script/hook/callback the runtime executes (hook), a user-facing entry point (command), or a point where a human chooses (human, hitl=true).
- var: shared state that routing depends on: phase/status fields, verdicts, flags like "checkpoint file exists", iteration counters. Files/messages used as channels are vars (their existence or status), NOT nodes.
- decision: any place an LLM or human picks among alternatives that affects control flow. outcomes = the full set, spelled exactly as in the source. The decision assigns var := outcome.
- edge: a control transfer src->dst (dispatch, invoke, hand off, return, loop back). guard = the condition in the expression language, or null. effect = assignments the transfer performs (e.g. the handoff that checks a box or sets a status).
- guard_kind says what the source means by the condition:
    only_if  = permission: "do X only when C" / "do not X unless C" (taking the edge when C is false breaks the rule)
    whenever = obligation: "when C, do X" / "if C you MUST X" (NOT taking the edge when C is true breaks the rule; taking it otherwise is fine)
    iff      = both stated ("do X when C, and only then")
    advisory = suggestion: "may", "optional", "consider", "recommended", "when helpful" (no rule; just a possible route)
- enforcement: "code" ONLY when a script/hook/config file mechanically blocks or forces the transfer AND you can see that its blocking action is one the host runtime honours (its documented blocking exit code / decision output) and that the names it compares match the names actually used by the dispatching side. If a script exists but either point is unverified, use "weak". "prose" when the rule is only an instruction in a prompt/document.
- loop: a cycle; back_edge = the edge id closing it; bound = numeric max iterations if stated, else null. Loops and edges model control transfer between actors. Rules about data contents (list sizes, file formats, log trimming, naming) are NOT control flow: omit them.
- node.effects: capabilities the node holds, from its declared tools/permissions: fs_write (writes files), shell (runs commands), src_mutate (edits source code), network, perm_bypass (declares elevated/bypassed permissions), spawn (dispatches sub-agents), editor. node.forbidden_effects: capabilities its instructions forbid it to use ("you NEVER write implementation code" on a node with Edit -> forbidden_effects: ["src_mutate"]).
- properties: rules that are not a single guarded transfer:
    only_after {node, after}: "node runs only after `after` has run" / "do B before A" / "A requires that B happened".
    never {node, unless, at}: a condition that must hold when the node starts (at=entry) or when it finishes (at=exit), e.g. "verdict is SOUND only if no kill-list items" -> never {node: skeptic, unless: "verdict != SOUND || kill_list_empty", at: exit}.
- forbidden transfer: "X never dispatches/invokes Y", "X does NOT do <what node Y does>" is an edge X->Y with guard "false", guard_kind only_if (taking it is the violation).
- expression language: `var == VALUE`, `var != VALUE`, `var < 3`, `!flag`, `flag`, `visited(node_id)`, combined with && || and parentheses. Use var ids and enum values exactly as declared; quote values that contain spaces or punctuation: review == "Approve all resolutions".
- ev: EVERY object must carry ev {file, line, text}; text is a distinctive substring (<= 80 chars) copied VERBATIM from exactly that numbered line (keep markup such as ** or ` as written). Never invent anchors.
- ids: lowercase snake_case derived from source names (file name, agent name, phase constant). Reuse the same id for the same entity everywhere; edges and properties may reference node ids defined in other files.
- node.aliases: EVERY surface name the source uses for the node, copied exactly as written: frontmatter name, file stem, invocation string ("Pkg:agent-name"), slash command, display name. A later pass links files by these names.
- refs: every name this chunk USES but does not define here: agents/skills it dispatches or compares against, commands it invokes, state files or values it checks. name is the exact string as written. List a ref even when you also emitted an edge for it.
- disposed: the user message ends with CANDIDATE RULE LINES. For EACH listed path:line output {"at": "path:line", "as": ...}: edge/property/forbidden_effect/decision/loop means you emitted a fact anchored at that line; data_rule = about contents or format, not control; duplicate = same rule already emitted from another line; not_a_rule = description, example or heading. Every candidate must be disposed.
Report only what this chunk evidences; other chunks cover other files. Prefer fewer, well-anchored facts over guesses."""

FOCUS = """Focus on ONE entity of the MAS. The user message gives its id, its names, the ids already known, and every source line across the repo that mentions it (with context). Report only facts about this entity: edges whose src or dst is it, decisions inside it, loops through it, its effects/forbidden_effects, properties (only_after/never) about it. Reuse the known ids exactly; create a new id only for an entity none of them names. Same schema and anchoring rules. Omit refs and disposed."""

# cue classes for candidate rule lines: deontic words, conditionals, control arrows, table rows that transfer control,
# and bullets under a heading that is itself a prohibition ("Red Flags", "Anti-patterns", "Never ...")
DEONTIC = re.compile(r"\b(must|never|only|before|after|require[sd]?|do not|don'?t|cannot|shall|always|unless|until|block(?:ed|s)?|exit\s+[1-9])\b", re.I)
COND = re.compile(r"^\s*(?:[-*\d.]+\s*)?\**\b(if|when|elif|else|for each|otherwise)\b|→|->|=>", re.I)
ROW = re.compile(r"^\s*\|(?!\s*-).*\b(invoke|dispatch|proceed|escalate|route|resume|skip|loop|stop|exit|return|present|ask|block)\w*\b", re.I)
HEAD = re.compile(r"^#+ .*\b(never|not|no|red flag|anti-?pattern|forbidden|prohibited|stop|avoid|rules?)\b", re.I)
FACTS = {"edge", "property", "forbidden_effect", "decision", "loop"}

UNIFY = """You are given the node and variable ids of a multi-agent system IR merged from several extraction chunks. Different chunks may have used different ids for the SAME entity (e.g. an agent's definition file vs. the step that dispatches it; a phase constant spelled two ways). Output ONLY a JSON object {"nodes": {"old_id": "canonical_id", ...}, "vars": {"old_id": "canonical_id", ...}} listing renames that merge duplicates. Only merge entities that are clearly the same thing. Do not invent new entities. Empty maps are fine."""


def collect(repo):
    """-> {relpath: [lines]} for text files under repo. Pure text; no path semantics."""
    files = {}
    for root, dirs, names in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for n in sorted(names):
            p = os.path.join(root, n)
            if not n.endswith(EXTS) or os.path.getsize(p) > MAX_FILE:
                continue
            try:
                with open(p, encoding="utf-8") as f:
                    files[os.path.relpath(p, repo)] = f.read().split("\n")
            except UnicodeDecodeError:
                pass
    return files


def chunk(files, limit=CHUNK_CHARS):
    """Group files by top-level dir, each chunk <= limit chars. Lines rendered `path:line| text`."""
    chunks, cur, cur_dir, size = [], [], None, 0
    for path, lines in files.items():
        top = os.path.dirname(path).split(os.sep)[0]
        text = "\n".join(f"{path}:{i + 1}| {l}" for i, l in enumerate(lines))
        if cur and (top != cur_dir or size + len(text) > limit):
            chunks.append("\n".join(cur)); cur, size = [], 0
        cur.append(text); size += len(text); cur_dir = top
    if cur:
        chunks.append("\n".join(cur))
    return chunks


def candidates(text):
    """`path:line` of every rendered line that may state a rule: the extractor must dispose of each one."""
    out, flagged = [], False
    for l in text.split("\n"):
        at, _, t = l.partition("| ")
        if t.startswith("#"):
            flagged = bool(HEAD.match(t))
        if DEONTIC.search(t) or COND.search(t) or ROW.match(t) or (flagged and t.lstrip().startswith(("-", "*"))):
            out.append(at)
    return out


def ask_json(system, user):
    msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    out = chat(msgs)
    try:
        return parse_json(out)
    except ValueError:
        msgs += [{"role": "assistant", "content": out},
                 {"role": "user", "content": "That was not valid JSON. Output only the JSON object."}]
        return parse_json(chat(msgs))


def _content(key, x):
    """What a fact says, ignoring its model-assigned id. Equal content means a real duplicate."""
    if key == "edges":
        return (x.src, x.dst, (x.guard or "").strip() or None, x.guard_kind, tuple(x.effect or ()), x.enforcement)
    if key == "decisions":
        return (x.node, x.var, tuple(sorted(map(str, x.outcomes))))
    if key == "loops":
        return (x.back_edge, x.bound, x.enforcement)
    if key == "refs":
        return (x.name,)
    return (x.kind, json.dumps(x.args, sort_keys=True))  # properties


def merge(partials, log=sys.stderr):
    """Combine per-chunk IRs without losing facts.

    Nodes and vars: same id = same entity; effects and values are unioned.
    Edges, decisions, loops: each chunk invents its own ids, so these are matched by
    content. An exact duplicate is dropped; anything else is kept, renamed on an id
    clash. The result over-approximates the MAS, so merging cannot remove a path or a
    check. Every merge, drop and rename is logged."""
    ir = IRM.IR()
    kept = {k: {} for k in IRM.LISTS}  # id -> (fact, chunk index)
    seen = {k: {} for k in IRM.LISTS}  # content -> kept id
    say = lambda msg: print(f"[merge] {msg}", file=log)
    for i, p in enumerate(partials):
        remap = {}  # this chunk's edge ids -> final ids, so its own loops still point at them
        for key in IRM.LISTS:  # edges come before loops
            for x in getattr(p, key):
                where = " ".join(w for w in (f"chunk {i}" if len(partials) > 1 else "", x.ev.file if x.ev else "") if w)
                prev = kept[key].get(x.id)
                if key in ("nodes", "vars") and prev:
                    y = prev[0]
                    if key == "nodes":
                        new = [e for e in x.effects if e not in y.effects]
                        y.effects += new
                        y.forbidden_effects += [e for e in x.forbidden_effects if e not in y.forbidden_effects]
                        y.aliases += [a for a in x.aliases if a not in y.aliases]
                        y.hitl = y.hitl or x.hitl
                        clash = f"; kind conflict, kept {y.kind!r} over {x.kind!r}" if x.kind != y.kind else ""
                        say(f"nodes/{x.id}: merged copy from {where}, added effects {new}{clash}")
                    else:
                        new = [v for v in x.values if v not in y.values]
                        y.values += new
                        clash = f"; type conflict, kept {y.type!r} over {x.type!r}" if x.type != y.type else ""
                        say(f"vars/{x.id}: merged copy from {where}, added values {new}{clash}")
                    continue
                if key not in ("nodes", "vars"):
                    if key == "loops":
                        x.back_edge = remap.get(x.back_edge, x.back_edge)
                    c = _content(key, x)
                    if c in seen[key]:
                        say(f"{key}/{x.id}: dropped, same content as {seen[key][c]} ({where})")
                        if key == "edges":
                            remap[x.id] = seen[key][c]
                        continue
                    if prev:
                        new_id, n = f"{x.id}__chunk{i}", 2
                        while new_id in kept[key]:
                            new_id, n = f"{x.id}__chunk{i}_{n}", n + 1
                        say(f"{key}/{x.id}: id already used by a different fact (chunk {prev[1]}), kept as {new_id} ({where})")
                        if key == "edges" and prev[1] != i:  # within one chunk the reference is ambiguous
                            remap[x.id] = new_id
                        x.id = new_id
                    seen[key][c] = x.id
                kept[key][x.id] = (x, i)
                getattr(ir, key).append(x)
    return ir


def _retext(text, mapping):
    """Apply id renames inside guard/effect/property text, whole words only."""
    if not text or not mapping:
        return text
    return re.sub(r"[A-Za-z_][\w.\-]*", lambda m: mapping.get(m[0], m[0]), text)


def rename(ir, nodes, vars_, log=sys.stderr):
    nodes = {k: v for k, v in nodes.items() if k != v}
    vars_ = {k: v for k, v in vars_.items() if k != v}
    n = lambda x: nodes.get(x, x)
    v = lambda x: vars_.get(x, x)
    both = {**vars_, **nodes}
    for e in ir.edges:
        e.src, e.dst = n(e.src), n(e.dst)
        e.guard = _retext(e.guard, both)
        e.effect = [_retext(a, vars_) for a in e.effect] if e.effect else e.effect
    for d in ir.decisions:
        d.node, d.var = n(d.node), v(d.var)
    for p in ir.properties:
        for k in ("node", "after"):
            if k in p.args:
                p.args[k] = n(p.args[k])
        for k in ("unless", "when"):
            if k in p.args:
                p.args[k] = _retext(p.args[k], both)
    for x in ir.nodes:
        if x.id in nodes:
            x.aliases.append(x.id)  # the old id stays a name of the merged entity
        x.id = n(x.id)
    for x in ir.vars:
        x.id = v(x.id)
    return merge([ir], log)


def _norm(s):
    return re.sub(r"[^a-z0-9]+", "_", str(s).lower()).strip("_")


def _lookup(names, k):
    """-> (node ids, exact). Loose: differs only by a qualifier prefix ("pkg:name" vs "name"), and unambiguous."""
    if k in names:
        return names[k], True
    loose = {ids[0]: ids for a, ids in names.items() if k.endswith("_" + a) or a.endswith("_" + k)}
    return (next(iter(loose.values())), False) if len(loose) == 1 else (None, False)


def link(ir, log=sys.stderr):
    """Deterministic linker. Nodes sharing a surface name are one entity; dangling edge endpoints and refs
    resolve against names. Returns {node_id: canonical_id}. Unresolved refs, qualifier-only matches and
    never-referenced nodes are logged: they are findings (or gaps) in their own right."""
    say = lambda m: print(f"[link] {m}", file=log)
    where = lambda x: f"{x.ev.file}:{x.ev.line}" if x.ev else "?"
    names = defaultdict(list)  # normalised surface name -> node ids, first definition first
    for n in ir.nodes:
        for a in [n.id, *n.aliases]:
            if n.id not in names[_norm(a)]:
                names[_norm(a)].append(n.id)
    parent = {}
    root = lambda x: x if parent.get(x, x) == x else root(parent[x])
    for a, ids in names.items():
        for other in ids[1:]:
            if root(other) != root(ids[0]):
                parent[root(other)] = root(ids[0]); say(f"nodes {other} = {ids[0]} (both named {a!r})")
    known = {n.id for n in ir.nodes}
    for e in ir.edges:  # endpoints that only another file defines
        for end in ("src", "dst"):
            x = getattr(e, end)
            ids, exact = _lookup(names, _norm(x)) if x not in known else (None, True)
            if ids:
                parent[x] = root(ids[0]); say(f"edge {e.id}.{end} {x!r} -> {ids[0]}" + ("" if exact else " (qualifier differs)"))
    referenced = set()
    for r in ir.refs:
        ids, exact = _lookup(names, _norm(r.name))
        if not ids:
            say(f"ref {r.name!r} ({where(r)}) matches no definition")
        else:
            referenced.add(root(ids[0]))
            if not exact:
                say(f"ref {r.name!r} ({where(r)}) matches {ids[0]} only up to a qualifier: check that the runtime compares them equal")
    incoming = {root(e.dst) for e in ir.edges}
    for n in ir.nodes:
        if root(n.id) == n.id and n.id not in referenced | incoming:
            say(f"node {n.id} ({where(n)}) is defined but nothing invokes or names it (gap)")
    return {x: root(x) for x in parent}


def focus(ir, files, log=sys.stderr, ctx=3, limit=CHUNK_CHARS):
    """Demand-driven pass: for each node, gather every line in the repo that names it and ask about it alone.
    Rules whose halves live in different files are only visible here."""
    known = {"nodes": [n.id for n in ir.nodes], "vars": [v.id for v in ir.vars]}

    def one(n):
        toks = {_norm(a) for a in [n.id, *n.aliases]} - {""}
        rx = re.compile("|".join(r"[\W_]*".join(map(re.escape, t.split("_"))) for t in toks), re.I)
        out = []
        for path, lines in files.items():
            hits = [i for i, l in enumerate(lines) if rx.search(l)]
            keep = sorted({j for i in hits for j in range(max(0, i - ctx), min(len(lines), i + ctx + 1))})
            out += [f"{path}:{j + 1}| {lines[j]}" for j in keep]
        text = "\n".join(out)
        print(f"[focus] {n.id}: {len(out)} lines" + (" (truncated)" if len(text) > limit else ""), file=log)
        msg = f"ENTITY: {n.id}\nNAMES: {[n.id, *n.aliases]}\nKNOWN IDS: {json.dumps(known)}\n\n{text[:limit]}"
        return IRM.from_dict(ask_json(SYSTEM + "\n\n" + FOCUS, msg))
    with ThreadPoolExecutor(int(os.environ.get("MAS2C_JOBS", "4"))) as ex:
        parts = list(ex.map(one, list(ir.nodes)))
    return merge([ir, *parts], log)


def extract(repo, name=None, log=sys.stderr):
    files = collect(repo)
    chunks = chunk(files)
    print(f"[extract] {len(files)} files, {len(chunks)} chunks", file=log)
    k = int(os.environ.get("MAS2C_SAMPLES", "1"))  # one LLM read misses rules at random; k reads are unioned

    def one(ics):
        i, c, s = ics
        cands = candidates(c)
        print(f"[extract] chunk {i + 1}/{len(chunks)}{f' sample {s + 1}/{k}' if k > 1 else ''} ({len(c)} chars, {len(cands)} candidate lines)", file=log)
        d = ask_json(SYSTEM, c + "\n\nCANDIDATE RULE LINES (dispose of each in `disposed`): " + " ".join(cands)
                     + (f"\n\n(independent reading {s + 1} of {k})" if k > 1 else ""))
        p = IRM.from_dict(d)
        anchored = {(x.ev.file, x.ev.line + k) for key in IRM.LISTS for x in getattr(p, key)
                    if x.ev and isinstance(x.ev.line, int) for k in range(-2, 3)}
        hist = Counter()
        for r in d.get("disposed") or []:
            if not isinstance(r, dict):
                continue
            f, _, ln = str(r.get("at", "")).rpartition(":")
            as_ = str(r.get("as"))
            hist[as_ + ("" if as_ not in FACTS or (f, int(ln) if ln.isdigit() else -1) in anchored else " (no fact anchored there)")] += 1
        hist["undisposed"] = max(0, len(cands) - sum(hist.values()))
        print(f"[extract] chunk {i + 1} dispositions: {dict(hist)}", file=log)
        return p
    with ThreadPoolExecutor(int(os.environ.get("MAS2C_JOBS", "4"))) as ex:
        partials = list(ex.map(one, [(i, c, s) for s in range(k) for i, c in enumerate(chunks)]))
    ir = merge(partials, log)
    ir = rename(ir, link(ir, log), {}, log)
    if len(chunks) > 1:
        summary = {"nodes": [{"id": n.id, "kind": n.kind, "file": n.ev.file if n.ev else None} for n in ir.nodes],
                   "vars": [{"id": v.id, "type": v.type, "values": v.values[:8]} for v in ir.vars]}
        r = ask_json(UNIFY, json.dumps(summary, indent=0))
        ir = rename(ir, r.get("nodes", {}) or {}, r.get("vars", {}) or {}, log)
    if os.environ.get("MAS2C_FOCUS", "1") != "0":
        ir = focus(ir, files, log)
        ir = rename(ir, link(ir, log), {}, log)
    ir.name = name or os.path.basename(os.path.abspath(repo))
    return ir, files
