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

python3 -m mas2c extract path/to/mas -o out/mas.ir.json   # LLM pass (cached in .mas2c-cache/)
python3 -m mas2c emit out/mas.ir.json -o out/mas.c        # deterministic; add --properties p.json
python3 -m mas2c all path/to/mas -o out                   # both

gcc -O1 -DMAS2C_TRACE out/mas.c -o out/mas && ./out/mas < input      # plain driver, prints path
clang -fsanitize=fuzzer,address -DMAS2C_NO_MAIN out/mas.c -o fuzz && ./fuzz   # libFuzzer
afl-cc out/mas.c -o mas_afl && afl-fuzz -i seeds -o findings -- ./mas_afl @@ # AFL++
```

A crash prints `UNWANTED <property_id>` and `abort()`s; the fuzz input is the witness path.
Re-running `extract` is free once cached (`MAS2C_CACHE` overrides the cache dir).

## Taxonomy (IR)

| Entity | Fields | Meaning |
|---|---|---|
| `Var` | `id type(enum/bool/int) init values ev` | Shared state routing depends on: phases, verdicts, "file exists" flags, counters. Files used as channels are vars. |
| `Node` | `id kind(agent/skill/hook/command/human) effects hitl ev` | Any actor/executable unit. `effects ⊆ {fs_write, shell, src_mutate, network, perm_bypass, spawn, editor}`. |
| `Decision` | `id node var outcomes ev` | An LLM/human choice; at fuzz time `var := outcomes[byte % n]`. |
| `Edge` | `id src dst guard effect enforcement ev` | Control transfer. `enforcement=code` ⇒ a script/hook/config mechanically enforces `guard`; `prose` ⇒ it is only an instruction. |
| `Loop` | `id back_edge bound enforcement ev` | A cycle and its (code- or prose-) bound. |
| `Property` | `id kind args ev` | What must not happen (see below). |
| `ev` | `file line text` | Evidence anchor; `text` is a verbatim substring of that line. |

Guard/effect mini-language: `var == V`, `var != V`, `var < 3`, `flag`, `!flag`, `visited(node)`,
combined with `&&`, `||`, parentheses; effects are `var = V`.

**The key modeling rule** (`mas2c/emit_c.py`): `code`-enforced guards compile into the C branch
condition (the fuzzer cannot violate them); `prose` guards do **not** — the edge is taken
nondeterministically and the guard becomes a property. Prose is what an LLM may ignore; code is
what it cannot.

## Properties

Built-ins are derived from the IR in `mas2c/verify.py:derive_properties`:

| id pattern | kind | trips when |
|---|---|---|
| `gate_bypass_<edge>` | `never {edge, unless}` | a prose-guarded edge is taken while its guard is false |
| `unbounded_<loop>` | `bounded {loop, n}` | a prose-bounded loop exceeds `n` (or `MAS2C_MAX_STEPS` if unbounded) |
| `unsafe_effect_<node>` | `only_after {node, after}` / `never {node, unless}` | a node with `shell`/`src_mutate`/`perm_bypass` effects runs without passing its nearest code gate / any incoming guard |

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
mas2c/extract.py   collect/chunk repo text, extraction + unification prompts, merge
mas2c/verify.py    anchor verification, reference resolution, built-in properties
mas2c/emit_c.py    expression compiler + C emitter
tests/             synthetic fixture MAS + hand-written IR; `python3 -m unittest discover -s tests`
test/darwin        example input MAS (git submodule) — test data only
```
