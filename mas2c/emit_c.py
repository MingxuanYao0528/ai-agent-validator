"""IR -> standalone C: one function per node, fuzz bytes drive every decision, properties abort()."""
import re
import sys

TOKEN = re.compile(r"""\|\||&&|==|!=|<=|>=|[<>!()]|"[^"]*"|'[^']*'|[\w.\-]+""")


class ExprError(ValueError):
    pass


def cid(s):
    return re.sub(r"\W", "_", str(s))


def _norm(s):
    return re.sub(r"[^a-z0-9]", "", str(s).lower())


class Compiler:
    def __init__(self, ir, log=sys.stderr):
        self.vars = {v.id: v for v in ir.vars}
        self.nodes = {n.id for n in ir.nodes}
        self.log = log

    # --- values -------------------------------------------------------------
    def value(self, var, tok):
        tok = tok.strip().strip("\"'")
        if var.type == "enum":
            if tok in var.values:
                return str(var.values.index(tok))
            n = _norm(tok)  # tolerate case/punctuation drift and unique abbreviations ("Approve" ~ "Approve all resolutions")
            hits = [v for v in var.values if _norm(v) == n] or ([v for v in var.values if _norm(v).startswith(n)] if n else [])
            if len(hits) == 1:
                print(f"[emit] note: value {tok!r} read as {hits[0]!r} for {var.id}", file=self.log)
                return str(var.values.index(hits[0]))
            raise ExprError(f"unknown value {tok!r} for enum {var.id} {var.values}")
        if var.type == "bool":
            return "1" if tok.lower() in ("true", "1", "yes") else "0"
        try:
            return str(int(tok))
        except ValueError:
            raise ExprError(f"non-integer value {tok!r} for int var {var.id}")

    def ref(self, name):
        if name not in self.vars:
            raise ExprError(f"unknown var {name!r}")
        return f"s->v_{cid(name)}"

    # --- expressions: or := and ('||' and)* ; and := unary ('&&' unary)* ; unary := '!' unary | '(' or ')' | atom
    def expr(self, text):
        self.toks = TOKEN.findall(text)
        self.i = 0
        out = self._or()
        if self.i != len(self.toks):
            raise ExprError(f"trailing tokens in {text!r}")
        return out

    def _peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _next(self):
        self.i += 1
        return self.toks[self.i - 1]

    def _or(self):
        parts = [self._and()]
        while self._peek() == "||":
            self._next(); parts.append(self._and())
        return " || ".join(parts) if len(parts) > 1 else parts[0]

    def _and(self):
        parts = [self._unary()]
        while self._peek() == "&&":
            self._next(); parts.append(self._unary())
        return "(" + " && ".join(parts) + ")" if len(parts) > 1 else parts[0]

    def _unary(self):
        t = self._peek()
        if t is None:
            raise ExprError("unexpected end")
        if t == "!":
            self._next(); return "!" + self._unary()
        if t == "(":
            self._next(); e = self._or()
            if self._next() != ")":
                raise ExprError("missing )")
            return "(" + e + ")"
        return self._atom()

    def _atom(self):
        name = self._next()
        if name == "visited" and self._peek() == "(":
            self._next(); node = self._next()
            if self._next() != ")" or node not in self.nodes:
                raise ExprError(f"bad visited({node})")
            return f"s->visited_{cid(node)}"
        if name.lower() in ("true", "false"):
            return "1" if name.lower() == "true" else "0"
        op = self._peek()
        if op in ("==", "!=", "<", "<=", ">", ">="):
            self._next()
            return f"({self.ref(name)} {op} {self.value(self.vars[name], self._next())})"
        return self.ref(name)

    def assign(self, text):
        m = re.fullmatch(r"\s*([\w.\-]+)\s*(\+=|-=|=)\s*(.+?)\s*", text)
        if not m:
            raise ExprError(f"bad assignment {text!r}")
        var, op, rhs = m.groups()
        ref = self.ref(var)
        inc = re.fullmatch(rf"{re.escape(var)}\s*([+-])\s*(\d+)", rhs)  # var = var + 1
        if inc:
            op, rhs = inc[1] + "=", inc[2]
        if op != "=":
            if self.vars[var].type != "int":
                raise ExprError(f"{op} on non-int var {var}")
            return f"{ref} {op} {int(rhs)};"
        return f"{ref} = {self.value(self.vars[var], rhs)};"


def emit(ir, log=sys.stderr):
    c = Compiler(ir, log)
    warn = lambda m: print(f"[emit] warning: {m}", file=log)
    nodes = [n.id for n in ir.nodes]
    out_edges = {n: [] for n in nodes}
    for e in ir.edges:
        out_edges[e.src].append(e)
    loops_by_edge = {}
    for l in ir.loops:
        loops_by_edge.setdefault(l.back_edge, []).append(l)
    decisions = {}
    for d in ir.decisions:
        decisions.setdefault(d.node, []).append(d)
    # properties by where they are checked
    at_entry, at_exit, at_edge, after_choice, at_loop = {}, {}, {}, {}, {}
    for p in ir.properties:
        a = p.args
        if p.kind == "never" and "edge" in a:
            at_edge.setdefault(a["edge"], []).append(p)
        elif p.kind == "must":
            after_choice.setdefault(a["edge"], []).append(p)
        elif p.kind == "bounded":
            at_loop.setdefault(a["loop"], []).append(p)
        elif p.kind in ("never", "only_after", "forbidden"):
            (at_exit if a.get("at") == "exit" else at_entry).setdefault(a["node"], []).append(p)
        else:
            warn(f"{p.id}: unknown property kind {p.kind!r}")

    def guarded(expr, what):
        try:
            return c.expr(expr)
        except ExprError as ex:
            warn(f"{what}: {ex} -> left unchecked")
            return None

    # property emitters, keyed by kind; add a kind here to extend
    def prop_never(p):
        e = guarded(p.args["unless"], p.id)
        return f'if (!({e})) unwanted("{p.id}");' if e else f"/* {p.id}: unparseable */"

    def prop_only_after(p):
        if p.args.get("after") not in c.nodes:
            warn(f"{p.id}: unknown node {p.args.get('after')!r}"); return f"/* {p.id}: unknown node */"
        return f'if (!s->visited_{cid(p.args["after"])}) unwanted("{p.id}");'

    def prop_bounded(p):
        return f'if (s->loop_{cid(p.args["loop"])} > {int(p.args["n"])}) unwanted("{p.id}");'

    def prop_forbidden(p):   # the agent holds the capability; the fuzzer decides whether it uses it
        return f'if (pick(2)) {{ TRACE("  effect {p.args["effect"]} @ {p.args["node"]} (forbidden)\\n"); unwanted("{p.id}"); }}'

    def prop_must(p, chosen_idx):  # obligation: condition held, a different edge was taken
        e = guarded(p.args["when"], p.id)
        return f'if (c != {chosen_idx} && ({e})) unwanted("{p.id}");' if e else f"/* {p.id}: unparseable */"

    PROPS = {"never": prop_never, "only_after": prop_only_after, "bounded": prop_bounded, "forbidden": prop_forbidden}

    L = []
    w = L.append
    w(f"/* Generated by mas2c from MAS '{ir.name}'. Standard C99; compile with gcc/clang, AFL++ (afl-cc) or")
    w(" * libFuzzer (clang -fsanitize=fuzzer -DMAS2C_NO_MAIN). -DMAS2C_TRACE prints the node path.")
    w(" * -DMAS2C_CONTINUE records every violated property once per run instead of aborting at the first. */")
    w("#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>")
    w(f"#ifndef MAS2C_MAX_STEPS\n#define MAS2C_MAX_STEPS {4 * len(nodes)}\n#endif")
    w("#ifdef MAS2C_TRACE\n#define TRACE(...) fprintf(stderr, __VA_ARGS__)\n#else\n#define TRACE(...) ((void)0)\n#endif")
    w("enum { " + ", ".join(f"N_{cid(n)}" for n in nodes) + " };")
    w("#ifdef MAS2C_TRACE\nstatic const char *NODE_NAME[] = { " + ", ".join(f'"{n}"' for n in nodes) + " };\n#endif")
    w("typedef struct {")
    for v in ir.vars:
        w(f"  int v_{cid(v.id)}; /* {v.type} {v.values if v.type == 'enum' else ''}{' env' if v.env else ''} */")
    for l in ir.loops:
        w(f"  int loop_{cid(l.id)};")
    for n in nodes:
        w(f"  int visited_{cid(n)};")
    w("  int step;\n} S;")
    w("static const uint8_t *in; static size_t in_len, in_pos;")
    w("static int pick(int n) { if (n <= 1) return 0; return in_pos < in_len ? in[in_pos++] % n : 0; }")
    w("#ifdef MAS2C_CONTINUE\nstatic const char *fired[256]; static int nfired;")
    w("static void unwanted(const char *p) {\n  for (int i = 0; i < nfired; i++) if (!strcmp(fired[i], p)) return;")
    w('  if (nfired < 256) fired[nfired++] = p;\n  fprintf(stderr, "UNWANTED %s\\n", p);\n}')
    w('#else\nstatic void unwanted(const char *p) { fprintf(stderr, "UNWANTED %s\\n", p); abort(); }\n#endif')
    w("static void init(S *s) {\n  memset(s, 0, sizeof *s);")
    for v in ir.vars:
        if v.env:  # external fact: fuzzer-chosen at start. ponytail: ints range 0..7; widen if a guard compares higher
            n = len(v.values) if v.type == "enum" else 2 if v.type == "bool" else 8
            w(f"  s->v_{cid(v.id)} = pick({n}); /* env */")
        else:
            val = v.values.index(v.init) if v.type == "enum" and v.init in v.values else (int(bool(v.init)) if v.type == "bool" else int(v.init or 0))
            w(f"  s->v_{cid(v.id)} = {val};")
    w("}")

    for n in ir.nodes:
        w(f"\n/* node {n.id} kind={n.kind} effects={n.effects} forbidden={n.forbidden_effects} hitl={n.hitl} ev={n.ev} */")
        w(f"static int node_{cid(n.id)}(S *s) {{\n  s->visited_{cid(n.id)}++;")
        for eff in n.effects:
            w(f'  TRACE("  effect {eff} @ {n.id}\\n");')
        for p in at_entry.get(n.id, []):
            w("  " + PROPS[p.kind](p))
        for d in decisions.get(n.id, []):
            v = c.vars[d.var]
            try:
                m = [c.value(v, o) for o in d.outcomes]
            except ExprError as ex:
                warn(f"decision {d.id}: {ex}"); continue
            w(f"  {{ static const int m[] = {{ {', '.join(m)} }}; s->v_{cid(d.var)} = m[pick({len(m)})]; }} /* decision {d.id}: {d.outcomes} */")
        for p in at_exit.get(n.id, []):
            w("  " + PROPS[p.kind](p))
        es = out_edges[n.id]
        if not es:
            w("  return -1;\n}"); continue
        w(f"  int cand[{len(es)}], nc = 0;")
        for i, e in enumerate(es):
            cond = "1"
            if e.guard and e.enforcement == "code":
                cond = guarded(e.guard, f"edge {e.id} guard") or "1"
            for l in loops_by_edge.get(e.id, []):
                if l.enforcement == "code" and l.bound is not None:
                    cond += f" && s->loop_{cid(l.id)} < {int(l.bound)}"
            w(f"  if ({cond}) cand[nc++] = {i}; /* {e.id}: {e.src} -> {e.dst} [{e.enforcement} {e.guard_kind}] {e.guard or ''} */")
        w("  if (!nc) return -1;\n  int c = nc == 1 ? cand[0] : cand[pick(nc)];")
        for i, e in enumerate(es):
            for p in after_choice.get(e.id, []):
                w("  " + prop_must(p, i))
        w("  switch (c) {")
        for i, e in enumerate(es):
            w(f"  case {i}:")
            for p in at_edge.get(e.id, []):
                w("    " + PROPS[p.kind](p))
            for l in loops_by_edge.get(e.id, []):
                w(f"    s->loop_{cid(l.id)}++;")
                for p in at_loop.get(l.id, []):
                    w("    " + PROPS[p.kind](p))
            for a in e.effect or []:
                try:
                    w("    " + c.assign(a))
                except ExprError as ex:
                    warn(f"edge {e.id} effect {a!r}: {ex}"); w(f"    /* effect {a!r}: unparseable */")
            w(f"    return N_{cid(e.dst)};")
        w("  }\n  return -1;\n}")

    w("\nstatic int dispatch(int n, S *s) {\n  switch (n) {")
    for n in nodes:
        w(f"  case N_{cid(n)}: return node_{cid(n)}(s);")
    w("  }\n  return -1;\n}")
    w("static void run(const uint8_t *buf, size_t len) {\n  S s; in = buf; in_len = len; in_pos = 0; init(&s);")
    w("#ifdef MAS2C_CONTINUE\n  nfired = 0;\n#endif")
    w(f"  int n = N_{cid(nodes[0])};\n  while (n >= 0 && s.step++ < MAS2C_MAX_STEPS) {{ TRACE(\"-> %s\\n\", NODE_NAME[n]); n = dispatch(n, &s); }}\n}}")
    w("int LLVMFuzzerTestOneInput(const uint8_t *d, size_t l) { run(d, l); return 0; }")
    w("#ifndef MAS2C_NO_MAIN\nint main(int argc, char **argv) {\n  static uint8_t buf[1 << 16];")
    w("  for (int i = 1; i < argc || (argc == 1 && i == 1); i++) {\n    FILE *f = argc == 1 ? stdin : fopen(argv[i], \"rb\");")
    w("    if (!f) { perror(argv[i]); return 2; }\n    size_t n = fread(buf, 1, sizeof buf, f); if (f != stdin) fclose(f);\n    run(buf, n);\n  }\n  return 0;\n}\n#endif")
    return "\n".join(L) + "\n"
