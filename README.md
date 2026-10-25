# mas2c — multi-agent systems as fuzzable C programs

`mas2c` turns a multi-agent system (MAS) — agents, prompts, hooks, scripts, in any framework —
into (1) a framework-neutral IR and (2) a standalone C program whose control flow mirrors the
MAS. Every LLM/human decision in the MAS becomes a byte of fuzz input, so off-the-shelf
program analysis (AFL++, libFuzzer, KLEE, CBMC) explores the MAS's paths and reports *unwanted
paths* as crashes.

```
MAS repo ──(LLM extraction, evidence-anchored)──► ir.json ──(deterministic emitter)──► mas.c
                                                     ▲                                  │
                                       properties.json (optional, user)      AFL++ / libFuzzer / KLEE / CBMC
```

No third-party Python dependencies (3.12 stdlib). No framework-specific parser: the frontend is
one LLM prompt over the repo's text, and every extracted fact must carry a `file:line` anchor
whose text is verified verbatim against the source; unverifiable facts are dropped.

## Usage

```bash
export OPENAI_BASE_URL=https://<any OpenAI-compatible endpoint>/v1
export OPENAI_API_KEY=...
export MAS2C_MODEL=cpa/claude-sonnet-5        # optional; any chat model
export MAS2C_JOBS=4                           # optional; parallel extraction chunks
export MAS2C_SAMPLES=1                        # optional; independent readings per chunk, unioned (see below)

python3 -m mas2c extract path/to/mas -o out/mas.ir.json   # LLM pass (cached in .mas2c-cache/)
python3 -m mas2c emit out/mas.ir.json -o out/mas.c        # deterministic; add --properties p.json
python3 -m mas2c all path/to/mas -o out                   # both

gcc -O1 -DMAS2C_TRACE out/mas.c -o out/mas && ./out/mas < input      # plain driver, prints path
clang -fsanitize=fuzzer,address -DMAS2C_NO_MAIN out/mas.c -o fuzz && ./fuzz   # libFuzzer
afl-cc out/mas.c -o mas_afl && afl-fuzz -i seeds -o findings -- ./mas_afl @@ # AFL++
```

A crash prints `UNWANTED <property_id>` and `abort()`s; the fuzz input is the witness path.
Build with `-DMAS2C_CONTINUE` to record every violated property once per run instead of stopping at
the first (for campaigns that enumerate findings; keep the default for AFL++/libFuzzer crash semantics).
Re-running `extract` is free once cached (`MAS2C_CACHE` overrides the cache dir).

### Extraction passes

Extraction is compile-then-link, not one big read:

1. **Local pass**, one LLM call per chunk (files grouped by top directory, ≤30k chars). Besides
   facts, each chunk reports the surface names it defines (`node.aliases`) and the names it uses but
   does not define (`refs`). The chunk also receives every *candidate rule line* — lines with a
   deontic word, a conditional, a control arrow, a control-transfer table row, or a bullet under a
   prohibition heading — and must dispose of each one (`edge|property|…|data_rule|duplicate|not_a_rule`);
   the log shows the disposition histogram, a completeness measure that needs no ground truth.
   A single reading misses rules at random (two readings of the same repo differed on a third of the
   rules each found); `MAS2C_SAMPLES=k` takes k independent readings and unions them, which `merge`
   makes safe because merging only adds paths and checks.
2. **Link pass**, deterministic (`extract.link`): nodes sharing a surface name are merged, dangling
   edge endpoints are resolved by name, and every `ref` is matched against the aliases. An unresolved
   ref, a ref that matches only up to a qualifier (`Pkg:name` vs `name`), and a node nothing invokes
   are logged as findings or gaps.
3. **Unify pass**, one LLM call over id summaries, for duplicates no shared name reveals.
4. **Focus pass** (`extract.focus`, disable with `MAS2C_FOCUS=0`): for each node, every line in the
   repo that names it is gathered (±3 lines) and one call asks about that node alone. Rules whose
   halves live in different files are only visible here. Output is merged and re-linked.

## Taxonomy (IR)

| Entity | Fields | Meaning |
|---|---|---|
| `Var` | `id type(enum/bool/int) init values env ev` | Shared state routing depends on: phases, verdicts, "file exists" flags, counters. Files used as channels are vars. `env` (set by `verify.resolve`): read but never assigned by any decision/effect, so it is an external fact the fuzzer chooses at the start of each run. |
| `Node` | `id kind(agent/skill/hook/command/human) effects forbidden_effects aliases hitl ev` | Any actor/executable unit. `effects` are the capabilities it holds (`⊆ {fs_write, shell, src_mutate, network, perm_bypass, spawn, editor}`); `forbidden_effects` are the ones its instructions forbid it to use. `aliases` are every surface name the source uses for it; the linker merges nodes that share one. |
| `Ref` | `id name ev` | A name a file uses but does not define (dispatched agent, invoked command, checked state file). The linker resolves it against node aliases; an unresolved ref or one that matches only up to a qualifier (`Pkg:name` vs `name`) is logged as a finding. |
| `Decision` | `id node var outcomes ev` | An LLM/human choice; at fuzz time `var := outcomes[byte % n]`. |
| `Edge` | `id src dst guard guard_kind effect enforcement ev` | Control transfer. `guard_kind`: `only_if` (permission: take only when guard), `whenever` (obligation: must take when guard), `iff` (both), `advisory` (a suggestion, no rule). `enforcement`: `code` (a script mechanically enforces it and its blocking action is verified), `weak` (a script exists but its blocking is unverified: treated as bypassable, alarm id `weak_gate_bypass_*`), `prose` (only an instruction). |
| `Loop` | `id back_edge bound enforcement ev` | A cycle and its (code- or prose-) bound. |
| `Property` | `id kind args ev` | What must not happen (see below). The extractor also emits `only_after` and `never` properties for stated ordering/invariant rules. |
| `ev` | `file line text` | Evidence anchor; `text` is a verbatim substring of that line. |

Guard/effect mini-language: `var == V`, `var != V`, `var < 3`, `flag`, `!flag`, `visited(node)`,
combined with `&&`, `||`, parentheses; effects are `var = V`.

**The key modeling rule** (`mas2c/emit_c.py`): `code`-enforced guards compile into the C branch
condition (the fuzzer cannot violate them); `prose` and `weak` guards do **not** — the edge is taken
nondeterministically and the guard becomes a property. Prose is what an LLM may ignore; code is
what it cannot. Likewise a forbidden capability is a fuzzer choice (`pick(2)`) at the node, and an
obligation (`whenever`) is checked after the route choice: condition held, a different edge taken.

## Properties

Built-ins are derived from the IR in `mas2c/verify.py:derive_properties`:

| id pattern | kind | trips when |
|---|---|---|
| `gate_bypass_<edge>` / `weak_gate_bypass_<edge>` | `never {edge, unless}` | an `only_if`/`iff` edge is taken while its guard is false (skipped when a `code` edge governs the same src→dst) |
| `obligation_<edge>` | `must {edge, when}` | a `whenever`/`iff` edge's condition held but another edge was taken |
| `unbounded_<loop>` | `bounded {loop, n}` | a prose-bounded loop exceeds its stated `n` (loops with no stated bound get a note, not an alarm) |
| `forbidden_effect_<node>_<eff>` | `forbidden {node, effect}` | the node uses a capability its instructions forbid |
| (extracted) | `only_after {node, after}`, `never {node, unless, at}` | ordering and invariant rules stated in the MAS |

Verify also folds case-split edges (same transition, guards `var == V` over one var) into one edge, and
reports source inconsistencies (one loop with two different bounds) and dangerous nodes with no guarded
incoming edge as notes rather than alarms.

User properties: a JSON list of the same objects passed with `--properties`, e.g.

```json
[{"id": "no_exec_without_verify", "kind": "only_after", "args": {"node": "executor", "after": "verify"}},
 {"id": "skeptic_max5",           "kind": "bounded",    "args": {"loop": "skeptic_revise", "n": 5}},
 {"id": "no_shell_unapproved",    "kind": "never",      "args": {"node": "executor", "unless": "approved && verdict == SOUND"}}]
```

## Extending

- **New property kind**: add an emitter to the `PROPS` dict in `mas2c/emit_c.py` (and, for a
  derived class, a block in `verify.derive_properties`).
- **New MAS framework**: nothing to do — the frontend is text-only. If precision on some
  framework is lacking, add a *hint collector* that pre-fills part of the IR from a formal
  artifact (e.g. a graph definition) and let `extract.merge` union it with the LLM's output.
- **Different LLM**: any OpenAI-compatible `/chat/completions` endpoint; set `MAS2C_MODEL`.

## Layout

```
mas2c/ir.py        taxonomy dataclasses, JSON I/O, schema text for the prompt
mas2c/llm.py       chat() over urllib + disk cache
mas2c/extract.py   collect/chunk repo text, candidate lines, extraction/unify/focus prompts, merge, link
mas2c/verify.py    anchor verification, reference resolution, built-in properties
mas2c/emit_c.py    expression compiler + C emitter
tests/             synthetic fixture MAS + hand-written IR; `python3 -m unittest discover -s tests`
test/darwin        example input MAS (git submodule) — test data only
```
