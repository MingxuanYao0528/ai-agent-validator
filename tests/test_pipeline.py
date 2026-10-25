import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from mas2c import ir as IRM                                   # noqa: E402
from mas2c.extract import collect, extract                    # noqa: E402
from mas2c.verify import check_anchors, resolve, derive_properties  # noqa: E402
from mas2c.emit_c import emit                                 # noqa: E402

FIXTURE = os.path.join(HERE, "fixture_mas")
NULL = open(os.devnull, "w")


def fixture_ir():
    return IRM.load(os.path.join(HERE, "fixture_ir.json"))


class Verify(unittest.TestCase):
    def test_anchor_check_keeps_good_drops_bad(self):
        ir, files = fixture_ir(), collect(FIXTURE)
        ir.nodes[0].ev.text = "this text is not on that line"
        dropped = check_anchors(ir, files, log=NULL)
        self.assertEqual([d[1] for d in dropped], ["planner"])
        self.assertEqual(len(ir.nodes), 4)

    def test_resolve_drops_dangling_and_adds_start(self):
        ir = fixture_ir()
        ir.edges.append(IRM.Edge(id="bad", src="planner", dst="ghost"))
        ir.edges.append(IRM.Edge(id="fake_code", src="planner", dst="auditor", guard="verdict == SOUND",
                                 enforcement="code", ev=IRM.Ev("planner.md", 9, "x")))
        resolve(ir, log=NULL)
        ids = {e.id for e in ir.edges}
        self.assertNotIn("bad", ids)
        self.assertEqual(next(e for e in ir.edges if e.id == "fake_code").enforcement, "prose")
        self.assertEqual(ir.nodes[0].id, "__start")
        self.assertEqual([e.dst for e in ir.edges if e.src == "__start"], ["planner"])

    def test_builtin_properties(self):
        ir = derive_properties(resolve(fixture_ir(), log=NULL), log=NULL)
        kinds = {p.id: p.kind for p in ir.properties}
        self.assertEqual(kinds["gate_bypass_e_handoff_executor"], "never")
        self.assertEqual(kinds["unbounded_revise_loop"], "bounded")
        self.assertEqual(kinds["unsafe_effect_executor"], "only_after")
        self.assertNotIn("gate_bypass_e_gate_pass", kinds)  # code-enforced: not bypassable


class Emit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        ir = derive_properties(resolve(fixture_ir(), log=NULL), log=NULL)
        cls.src = os.path.join(cls.tmp, "f.c")
        with open(cls.src, "w") as f:
            f.write(emit(ir, log=NULL))
        cls.bin = os.path.join(cls.tmp, "f")
        subprocess.run(["gcc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-O1", "-DMAS2C_TRACE", cls.src, "-o", cls.bin], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def run_input(self, data):
        p = subprocess.run([self.bin], input=data, capture_output=True)
        return p.returncode, p.stderr.decode()

    def test_empty_input_terminates_cleanly(self):
        rc, err = self.run_input(b"")
        self.assertEqual(rc, 0, err)
        self.assertIn("-> executor", err)

    def test_prose_gate_bypass_is_reachable(self):
        rc, err = self.run_input(b"\x01")
        self.assertNotEqual(rc, 0)
        self.assertIn("UNWANTED gate_bypass_e_handoff_executor", err)

    def test_prose_loop_bound_trips(self):
        rc, err = self.run_input(b"\x00\x01\x01" * 5)
        self.assertNotEqual(rc, 0)
        self.assertIn("UNWANTED unbounded_revise_loop", err)

    def test_code_gate_never_bypassed(self):
        for i in range(0, 256, 8):
            rc, err = self.run_input(bytes([i, i >> 1, i >> 2, 7, 3]))
            self.assertNotIn("UNWANTED unsafe_effect_executor", err)


@unittest.skipUnless(os.environ.get("OPENAI_BASE_URL"), "needs OPENAI_BASE_URL")
class Extract(unittest.TestCase):
    def test_extract_fixture(self):
        ir, files = extract(FIXTURE, log=NULL)
        check_anchors(ir, files, log=NULL)
        resolve(ir, log=NULL)
        ids = {n.id for n in ir.nodes}
        self.assertTrue({"planner", "executor"} <= ids, ids)
        self.assertTrue(any(e.enforcement == "code" for e in ir.edges), "gate.sh should yield a code-enforced edge")
        self.assertTrue(any(l.bound == 3 for l in ir.loops), [l.bound for l in ir.loops])


if __name__ == "__main__":
    unittest.main()
