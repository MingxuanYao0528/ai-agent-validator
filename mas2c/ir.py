"""Framework-neutral MAS IR. Every fact carries an evidence anchor (file:line + verbatim text)."""
import json
from dataclasses import dataclass, field, fields, asdict
from typing import Optional

EFFECTS = ["fs_write", "shell", "src_mutate", "network", "perm_bypass", "spawn", "editor"]
DANGEROUS = {"shell", "src_mutate", "perm_bypass"}
NODE_KINDS = ["agent", "skill", "hook", "command", "human"]
CODE_EXTS = (".sh", ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml")


@dataclass
class Ev:
    file: str
    line: int
    text: str


@dataclass
class Var:
    id: str
    type: str                      # enum | bool | int
    init: object = None
    values: list = field(default_factory=list)
    ev: Optional[Ev] = None


@dataclass
class Node:
    id: str
    kind: str                      # agent | skill | hook | command | human
    effects: list = field(default_factory=list)
    hitl: bool = False
    ev: Optional[Ev] = None


@dataclass
class Decision:
    id: str
    node: str
    var: str
    outcomes: list
    ev: Optional[Ev] = None


@dataclass
class Edge:
    id: str
    src: str
    dst: str
    guard: Optional[str] = None
    effect: Optional[list] = None  # ["var = VALUE", ...]
    enforcement: str = "prose"     # code | prose
    ev: Optional[Ev] = None


@dataclass
class Loop:
    id: str
    back_edge: str
    bound: Optional[int] = None
    enforcement: str = "prose"
    ev: Optional[Ev] = None


@dataclass
class Property:
    id: str
    kind: str                      # never | only_after | bounded
    args: dict = field(default_factory=dict)
    ev: Optional[Ev] = None


@dataclass
class IR:
    name: str = "mas"
    vars: list = field(default_factory=list)
    nodes: list = field(default_factory=list)
    decisions: list = field(default_factory=list)
    edges: list = field(default_factory=list)
    loops: list = field(default_factory=list)
    properties: list = field(default_factory=list)


LISTS = {"vars": Var, "nodes": Node, "decisions": Decision, "edges": Edge, "loops": Loop, "properties": Property}


def _build(cls, d):
    """Construct dataclass from dict, ignoring unknown keys (LLM output is lenient)."""
    known = {f.name for f in fields(cls)}
    kw = {k: v for k, v in d.items() if k in known}
    if isinstance(kw.get("ev"), dict):
        kw["ev"] = _build(Ev, kw["ev"])
    elif "ev" in kw and not isinstance(kw["ev"], Ev):
        kw["ev"] = None
    return cls(**kw)


def from_dict(d):
    ir = IR(name=d.get("name", "mas"))
    for key, cls in LISTS.items():
        for item in d.get(key, []) or []:
            if isinstance(item, dict) and "id" in item:
                try:
                    setattr(ir, key, getattr(ir, key) + [_build(cls, item)])
                except TypeError:
                    pass  # missing required field: drop
    return ir


def to_dict(ir):
    return asdict(ir)


def load(path):
    with open(path) as f:
        return from_dict(json.load(f))


def dump(ir, path):
    with open(path, "w") as f:
        json.dump(to_dict(ir), f, indent=1)


SCHEMA = """{
 "vars":      [{"id": "snake_id", "type": "enum|bool|int", "init": "<value>", "values": ["V1","V2"], "ev": EV}],
 "nodes":     [{"id": "snake_id", "kind": "agent|skill|hook|command|human", "effects": ["fs_write|shell|src_mutate|network|perm_bypass|spawn|editor"], "hitl": false, "ev": EV}],
 "decisions": [{"id": "snake_id", "node": "node_id", "var": "var_id", "outcomes": ["V1","V2"], "ev": EV}],
 "edges":     [{"id": "snake_id", "src": "node_id", "dst": "node_id", "guard": "expr or null", "effect": ["var = V1"] , "enforcement": "code|prose", "ev": EV}],
 "loops":     [{"id": "snake_id", "back_edge": "edge_id", "bound": 5, "enforcement": "code|prose", "ev": EV}]
}
EV = {"file": "relative/path", "line": 12, "text": "verbatim substring of that line"}"""
