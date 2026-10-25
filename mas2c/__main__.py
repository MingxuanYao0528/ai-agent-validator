"""mas2c: MAS repo -> IR (JSON) -> C fuzz target.
  python3 -m mas2c extract REPO -o ir.json
  python3 -m mas2c emit ir.json -o out.c [--properties props.json] [--no-builtin]
  python3 -m mas2c all REPO -o outdir
"""
import argparse
import json
import os
import sys
from . import ir as IRM
from .extract import extract
from .verify import check_anchors, resolve, derive_properties
from .emit_c import emit


def do_extract(repo, out, name=None):
    ir, files = extract(repo, name)
    check_anchors(ir, files)
    resolve(ir)
    IRM.dump(ir, out)
    print(f"[mas2c] {out}: {len(ir.nodes)} nodes, {len(ir.vars)} vars, {len(ir.decisions)} decisions, "
          f"{len(ir.edges)} edges, {len(ir.loops)} loops", file=sys.stderr)
    return ir


def do_emit(ir_path, out, props=None, builtin=True):
    ir = IRM.load(ir_path)
    resolve(ir)
    if builtin:
        derive_properties(ir)
    if props:
        with open(props) as f:
            ir.properties += [IRM._build(IRM.Property, p) for p in json.load(f)]
    with open(out, "w") as f:
        f.write(emit(ir))
    print(f"[mas2c] {out}: {len(ir.properties)} properties", file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="mas2c", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("extract"); p.add_argument("repo"); p.add_argument("-o", default="ir.json"); p.add_argument("--name")
    p = sub.add_parser("emit"); p.add_argument("ir"); p.add_argument("-o", default="out.c")
    p.add_argument("--properties"); p.add_argument("--no-builtin", action="store_true")
    p = sub.add_parser("all"); p.add_argument("repo"); p.add_argument("-o", default="out"); p.add_argument("--properties")
    a = ap.parse_args(argv)
    if a.cmd == "extract":
        do_extract(a.repo, a.o, a.name)
    elif a.cmd == "emit":
        do_emit(a.ir, a.o, a.properties, not a.no_builtin)
    else:
        os.makedirs(a.o, exist_ok=True)
        name = os.path.basename(os.path.abspath(a.repo))
        irp = os.path.join(a.o, name + ".ir.json")
        do_extract(a.repo, irp, name)
        do_emit(irp, os.path.join(a.o, name + ".c"), a.properties)


if __name__ == "__main__":
    main()
