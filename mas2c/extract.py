"""General LLM-driven frontend: any MAS repo -> IR. No framework-specific parsing."""
import json
import os
import sys
from . import ir as IRM
from .llm import chat, parse_json

EXTS = (".md", ".txt", ".json", ".yaml", ".yml", ".sh", ".py", ".toml", ".ts", ".js")
SKIP_DIRS = {".git", "node_modules", "__pycache__"}
MAX_FILE = 200_000
CHUNK_CHARS = 30_000

SYSTEM = """You extract a multi-agent system (MAS) into a formal IR for program analysis (fuzzing).
Output ONLY one JSON object with keys vars, nodes, decisions, edges, loops. Schema:
""" + IRM.SCHEMA + """

Framework-agnostic definitions:
- node: an actor or executable unit: an agent/LLM role (agent), a procedure/skill/prompt template an agent invokes in-context (skill), a script/hook/callback the runtime executes (hook), a user-facing entry point (command), or a point where a human chooses (human, hitl=true).
- var: shared state that routing depends on: phase/status fields, verdicts, flags like "checkpoint file exists", iteration counters. Files/messages used as channels are vars (their existence or status), NOT nodes.
- decision: any place an LLM or human picks among alternatives that affects control flow. outcomes = the full set, spelled exactly as in the source. The decision assigns var := outcome.
- edge: a control transfer src->dst (dispatch, invoke, hand off, return, loop back). guard = condition (expression language below) or null. effect = assignments the transfer performs. enforcement = "code" ONLY when a script/hook/config file mechanically enforces the guard (ev must cite that file); "prose" when it is only an instruction in a prompt/document.
- loop: a cycle; back_edge = the edge id closing it; bound = numeric max iterations if stated, else null; enforcement code/prose as above.
- node.effects: fs_write (writes files), shell (runs commands), src_mutate (edits source code), network, perm_bypass (declares elevated/bypassed permissions), spawn (dispatches sub-agents), editor. Derive from declared tools/permissions/instructions.
- expression language: `var == VALUE`, `var != VALUE`, `var < 3`, `!flag`, `flag`, `visited(node_id)`, combined with && || and parentheses. Use var ids and enum values exactly as declared.
- ev: EVERY object must carry ev {file, line, text}; text is a distinctive substring (<= 80 chars) copied VERBATIM from exactly that numbered line. Never invent anchors.
- ids: lowercase snake_case derived from source names (file name, agent name, phase constant). Reuse the same id for the same entity everywhere; edges may reference node ids defined in other files.
Report only what this chunk evidences; other chunks cover other files. Prefer fewer, well-anchored facts over guesses."""

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
        return (x.src, x.dst, (x.guard or "").strip() or None, tuple(x.effect or ()), x.enforcement)
    if key == "decisions":
        return (x.node, x.var, tuple(sorted(map(str, x.outcomes))))
    if key == "loops":
        return (x.back_edge, x.bound, x.enforcement)
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


def rename(ir, nodes, vars_, log=sys.stderr):
    nodes = {k: v for k, v in nodes.items() if k != v}
    vars_ = {k: v for k, v in vars_.items() if k != v}
    n = lambda x: nodes.get(x, x)
    v = lambda x: vars_.get(x, x)
    for e in ir.edges:
        e.src, e.dst = n(e.src), n(e.dst)
    for d in ir.decisions:
        d.node, d.var = n(d.node), v(d.var)
    for x in ir.nodes:
        x.id = n(x.id)
    for x in ir.vars:
        x.id = v(x.id)
    return merge([ir], log)


def extract(repo, name=None, log=sys.stderr):
    files = collect(repo)
    chunks = chunk(files)
    print(f"[extract] {len(files)} files, {len(chunks)} chunks", file=log)
    from concurrent.futures import ThreadPoolExecutor

    def one(ic):
        i, c = ic
        print(f"[extract] chunk {i + 1}/{len(chunks)} ({len(c)} chars)", file=log)
        return IRM.from_dict(ask_json(SYSTEM, c))
    with ThreadPoolExecutor(int(os.environ.get("MAS2C_JOBS", "4"))) as ex:
        partials = list(ex.map(one, enumerate(chunks)))
    ir = merge(partials, log)
    ir.name = name or os.path.basename(os.path.abspath(repo))
    if len(chunks) > 1:
        summary = {"nodes": [{"id": n.id, "kind": n.kind, "file": n.ev.file if n.ev else None} for n in ir.nodes],
                   "vars": [{"id": v.id, "type": v.type, "values": v.values[:8]} for v in ir.vars]}
        r = ask_json(UNIFY, json.dumps(summary, indent=0))
        ir = rename(ir, r.get("nodes", {}) or {}, r.get("vars", {}) or {}, log)
        ir.name = name or os.path.basename(os.path.abspath(repo))
    return ir, files
