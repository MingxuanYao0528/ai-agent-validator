"""General LLM-driven frontend: any MAS repo -> IR. No framework-specific parsing."""
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


def merge(partials):
    """Union by id; same-id vars union values, nodes union effects; duplicate edges (src,dst,guard) dropped."""
    ir = IRM.IR()
    seen = {k: {} for k in IRM.LISTS}
    for p in partials:
        for key in IRM.LISTS:
            for item in getattr(p, key):
                prev = seen[key].get(item.id)
                if prev is None:
                    seen[key][item.id] = item
                    getattr(ir, key).append(item)
                elif key == "vars":
                    prev.values += [v for v in item.values if v not in prev.values]
                elif key == "nodes":
                    prev.effects += [e for e in item.effects if e not in prev.effects]
                    prev.hitl = prev.hitl or item.hitl
    sig = set()
    ir.edges = [e for e in ir.edges if (e.src, e.dst, e.guard) not in sig and not sig.add((e.src, e.dst, e.guard))]
    return ir


def rename(ir, nodes, vars_):
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
    return merge([ir])


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
    ir = merge(partials)
    ir.name = name or os.path.basename(os.path.abspath(repo))
    if len(chunks) > 1:
        import json
        summary = {"nodes": [{"id": n.id, "kind": n.kind, "file": n.ev.file if n.ev else None} for n in ir.nodes],
                   "vars": [{"id": v.id, "type": v.type, "values": v.values[:8]} for v in ir.vars]}
        r = ask_json(UNIFY, json.dumps(summary, indent=0))
        ir = rename(ir, r.get("nodes", {}) or {}, r.get("vars", {}) or {})
        ir.name = name or os.path.basename(os.path.abspath(repo))
    return ir, files
