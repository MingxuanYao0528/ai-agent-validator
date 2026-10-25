import copy
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from mas2c import ir as IRM                                   # noqa: E402
from mas2c.extract import collect, extract, merge, rename, link, candidates  # noqa: E402
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
        self.assertEqual(len(ir.nodes), 5)

    def test_resolve_drops_dangling_and_adds_start(self):
        ir = fixture_ir()
        ir.edges.append(IRM.Edge(id="bad", src="planner", dst="ghost"))
        ir.edges.append(IRM.Edge(id="fake_code", src="planner", dst="auditor", guard="verdict == SOUND",
                                 enforcement="code", ev=IRM.Ev("planner.md", 9, "x")))
        ir.properties.append(IRM.Property(id="dangling", kind="only_after", args={"node": "executor", "after": "ghost"}))
        resolve(ir, log=NULL)
        ids = {e.id for e in ir.edges}
        self.assertNotIn("bad", ids)
        self.assertEqual(next(e for e in ir.edges if e.id == "fake_code").enforcement, "prose")
        self.assertEqual([p.id for p in ir.properties], ["exec_after_plan"])
        self.assertEqual(ir.nodes[0].id, "__start")
        self.assertEqual([e.dst for e in ir.edges if e.src == "__start"], ["planner"])

    def test_resolve_marks_env_vars_and_drops_advisory_guards(self):
        ir = resolve(fixture_ir(), log=NULL)
        v = {x.id: x for x in ir.vars}
        self.assertTrue(v["approved"].env is False)      # set by e_user_approve
        self.assertTrue(v["verdict"].env is False)       # set by a decision
        self.assertIsNone(next(e for e in ir.edges if e.id == "e_consult").guard)

    def test_resolve_declares_undeclared_vars_as_env(self):
        ir = fixture_ir()
        ir.properties.append(IRM.Property(id="p", kind="never", args={"node": "executor", "unless": 'mood == "calm" || !tired || n < 3'},
                                          ev=IRM.Ev("executor.md", 4, "x")))
        resolve(ir, log=NULL)
        v = {x.id: (x.type, x.env, x.values) for x in ir.vars}
        self.assertEqual(v["mood"], ("enum", True, ["calm"]))
        self.assertEqual(v["tired"], ("bool", True, []))
        self.assertEqual(v["n"][:2], ("int", True))

    def test_resolve_folds_case_splits(self):
        ir = fixture_ir()
        ir.edges += [IRM.Edge(id="a", src="auditor", dst="user", guard="verdict == SOUND", ev=IRM.Ev("planner.md", 13, "x")),
                     IRM.Edge(id="b", src="auditor", dst="user", guard="verdict == UNSOUND", ev=IRM.Ev("planner.md", 13, "x"))]
        resolve(ir, log=NULL)
        guards = [e.guard for e in ir.edges if e.src == "auditor" and e.dst == "user"]
        self.assertEqual(guards, [None, "verdict == SOUND || verdict == UNSOUND"])

    def test_builtin_properties(self):
        ir = derive_properties(resolve(fixture_ir(), log=NULL), log=NULL)
        kinds = {p.id: p.kind for p in ir.properties}
        self.assertEqual(kinds["gate_bypass_e_handoff_executor"], "never")
        self.assertEqual(kinds["gate_bypass_e_revise"], "never")          # iff: permission half
        self.assertEqual(kinds["obligation_e_revise"], "must")             # iff: obligation half
        self.assertEqual(kinds["unbounded_revise_loop"], "bounded")
        self.assertEqual(kinds["forbidden_effect_planner_shell"], "forbidden")
        self.assertEqual(kinds["weak_gate_bypass_e_gate_pass"], "never")   # weak: alarm, not lock
        self.assertEqual(kinds["exec_after_plan"], "only_after")           # extracted rule kept
        self.assertNotIn("gate_bypass_e_consult", kinds)                   # advisory: no rule
        self.assertFalse(any(k.startswith("unsafe_effect") for k in kinds))


class Merge(unittest.TestCase):
    def test_merge_keeps_conflicting_facts_and_drops_only_exact_duplicates(self):
        a = IRM.from_dict({
            "nodes": [{"id": "planner", "kind": "agent", "effects": ["fs_write"]}],
            "vars": [{"id": "verdict", "type": "enum", "values": ["SOUND", "UNSOUND"]}],
            "edges": [{"id": "e1", "src": "planner", "dst": "auditor"},
                      {"id": "e2", "src": "planner", "dst": "executor", "guard": "verdict == SOUND"}]})
        b = IRM.from_dict({
            "nodes": [{"id": "planner", "kind": "skill", "effects": ["spawn"]}],
            "vars": [{"id": "verdict", "type": "enum", "values": ["SOUND", "NONE"]}],
            "edges": [{"id": "e2", "src": "gate", "dst": "executor", "guard": "approved", "enforcement": "code"},
                      {"id": "e3", "src": "planner", "dst": "auditor"}],
            "loops": [{"id": "l_own", "back_edge": "e2", "bound": 3},
                      {"id": "l_dup", "back_edge": "e3", "bound": 5}]})
        m = merge([a, b], log=NULL)
        edges = {e.id: (e.src, e.dst, e.guard) for e in m.edges}
        self.assertEqual(edges, {"e1": ("planner", "auditor", None),
                                 "e2": ("planner", "executor", "verdict == SOUND"),
                                 "e2__chunk1": ("gate", "executor", "approved")})
        self.assertEqual({l.id: l.back_edge for l in m.loops}, {"l_own": "e2__chunk1", "l_dup": "e1"})
        self.assertEqual(m.nodes[0].effects, ["fs_write", "spawn"])
        self.assertEqual(m.vars[0].values, ["SOUND", "UNSOUND", "NONE"])

    def test_same_edge_with_different_enforcement_is_kept_twice(self):
        a = IRM.from_dict({"edges": [{"id": "e", "src": "x", "dst": "y", "guard": "ok", "enforcement": "code"}]})
        b = IRM.from_dict({"edges": [{"id": "e", "src": "x", "dst": "y", "guard": "ok", "enforcement": "prose"}]})
        self.assertEqual([e.enforcement for e in merge([a, b], log=NULL).edges], ["code", "prose"])

    def test_rename_rewrites_expressions(self):
        ir = IRM.from_dict({
            "vars": [{"id": "skeptic_result", "type": "enum", "values": ["SOUND"]}, {"id": "verdict", "type": "enum", "values": ["SOUND"]}],
            "nodes": [{"id": "skeptic_step", "kind": "skill"}, {"id": "darwin_skeptic", "kind": "agent"}, {"id": "revise", "kind": "agent"}],
            "edges": [{"id": "e", "src": "skeptic_step", "dst": "revise", "guard": "skeptic_result != SOUND && visited(skeptic_step)",
                       "effect": ["skeptic_result = SOUND"]}],
            "properties": [{"id": "p", "kind": "never", "args": {"node": "skeptic_step", "unless": "skeptic_result == SOUND"}}]})
        u = rename(ir, {"skeptic_step": "darwin_skeptic"}, {"skeptic_result": "verdict"}, log=NULL)
        e = u.edges[0]
        self.assertEqual((e.src, e.guard, e.effect), ("darwin_skeptic", "verdict != SOUND && visited(darwin_skeptic)", ["verdict = SOUND"]))
        self.assertEqual(u.properties[0].args, {"node": "darwin_skeptic", "unless": "verdict == SOUND"})
        self.assertEqual([v.id for v in u.vars], ["verdict"])


class Link(unittest.TestCase):
    def test_link_merges_by_alias_resolves_endpoints_and_reports_gaps(self):
        ir = IRM.from_dict({
            "nodes": [{"id": "worker_agent", "kind": "agent", "aliases": ["darwin-worker"], "ev": {"file": "a.md", "line": 1, "text": "x"}},
                      {"id": "worker", "kind": "agent", "aliases": ["darwin-worker", "Darwin:darwin-worker"]},
                      {"id": "orphan", "kind": "agent", "ev": {"file": "o.md", "line": 1, "text": "x"}}],
            "edges": [{"id": "e", "src": "spec", "dst": "darwin_worker"}],       # 'spec' defined nowhere, dst by surface name
            "refs": [{"id": "r1", "name": "darwin-worker"}, {"id": "r2", "name": "ghost-agent", "ev": {"file": "h.sh", "line": 3, "text": "x"}}]})
        log = io.StringIO()
        u = rename(ir, link(ir, log), {}, log=NULL)
        self.assertEqual([n.id for n in u.nodes], ["worker_agent", "orphan"])
        self.assertEqual(sorted(u.nodes[0].aliases), ["Darwin:darwin-worker", "darwin-worker", "worker"])
        self.assertEqual((u.edges[0].src, u.edges[0].dst), ("spec", "worker_agent"))
        out = log.getvalue()
        self.assertIn("ref 'ghost-agent' (h.sh:3) matches no definition", out)
        self.assertIn("node orphan (o.md:1) is defined but nothing invokes or names it (gap)", out)

    def test_link_reports_qualifier_only_matches(self):
        ir = IRM.from_dict({"nodes": [{"id": "worker", "kind": "agent", "aliases": ["darwin-worker"]}],
                            "refs": [{"id": "r", "name": "Darwin:darwin-worker"}]})
        log = io.StringIO(); link(ir, log)
        self.assertIn("only up to a qualifier", log.getvalue())

    def test_candidates_pick_deontic_lines(self):
        text = ("a.md:1| # Title\na.md:2| You MUST run tests first.\nh.sh:3| exit 1\na.md:4| Some prose only here\na.md:5| nothing\n"
                "a.md:6| If mode is fast:\na.md:7| | **DONE** | Invoke `next` |\na.md:8| | col | col |\na.md:9| ## Red Flags (STOP)\n"
                "a.md:10| - Skipping tasks\na.md:11| text\na.md:12| ## Example\na.md:13| - a bullet")
        self.assertEqual(candidates(text), ["a.md:2", "h.sh:3", "a.md:4", "a.md:6", "a.md:7", "a.md:10"])


class Emit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        ir = fixture_ir()
        ir.vars.append(IRM.Var(id="weather", type="enum", values=["SUN", "RAIN"], init="SUN"))
        ir.edges.append(IRM.Edge(id="e_rain", src="researcher", dst="user", guard="weather == rain", ev=IRM.Ev("planner.md", 16, "x")))
        ir = derive_properties(resolve(ir, log=NULL), log=NULL)   # weather is read, never set -> env
        cls.src = os.path.join(cls.tmp, "f.c")
        cls.log = io.StringIO()
        with open(cls.src, "w") as f:
            f.write(emit(ir, log=cls.log))
        cls.bins = {}
        for mode, flags in (("abort", []), ("cont", ["-DMAS2C_CONTINUE"])):
            cls.bins[mode] = os.path.join(cls.tmp, mode)
            subprocess.run(["gcc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-O1", "-DMAS2C_TRACE", *flags, cls.src, "-o", cls.bins[mode]], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def run_input(self, data, mode="abort"):
        p = subprocess.run([self.bins[mode]], input=data, capture_output=True)
        return p.returncode, p.stderr.decode()

    def test_env_var_is_fuzzer_chosen_and_values_match_tolerantly(self):
        src = open(self.src).read()
        self.assertIn("s->v_weather = pick(2); /* env */", src)
        self.assertIn("read as 'RAIN'", self.log.getvalue())   # "rain" ~ "RAIN"

    def test_empty_input_terminates_cleanly(self):
        rc, err = self.run_input(b"")
        self.assertEqual(rc, 0, err)
        self.assertIn("-> executor", err)

    def test_prose_gate_bypass_is_reachable(self):
        # bytes: env weather, planner forbidden-shell choice, planner door 1 of 3 (handoff) with verdict NONE
        rc, err = self.run_input(b"\x00\x00\x01")
        self.assertNotEqual(rc, 0)
        self.assertIn("UNWANTED gate_bypass_e_handoff_executor", err)

    def test_obligation_trips_when_condition_holds_but_edge_not_taken(self):
        # env, no shell, planner->auditor(0), verdict UNSOUND(1), auditor picks escalate(0) instead of revise
        rc, err = self.run_input(b"\x00\x00\x00\x01\x00")
        self.assertNotEqual(rc, 0)
        self.assertIn("UNWANTED obligation_e_revise", err)

    def test_forbidden_effect_is_a_fuzzer_choice(self):
        rc, err = self.run_input(b"\x00\x01" + b"\x00" * 8, "cont")
        self.assertIn("UNWANTED forbidden_effect_planner_shell", err)

    def test_weak_gate_is_bypassable_and_lock_would_not_be(self):
        rc, err = self.run_input(b"\x00\x00\x01", "cont")   # straight to the gate, approved still false
        found = set(re.findall(r"UNWANTED (\S+)", err))
        self.assertEqual(found, {"gate_bypass_e_handoff_executor", "weak_gate_bypass_e_gate_pass"})
        self.assertIn("-> executor", err)                       # weak = alarm, not lock: the run gets through

    def test_continue_mode_reports_each_property_once_and_exits_zero(self):
        rc, err = self.run_input(b"\x00\x00\x01", "cont")
        self.assertEqual(rc, 0)
        lines = [l for l in err.splitlines() if l.startswith("UNWANTED")]
        self.assertEqual(len(lines), len(set(lines)))
        self.assertTrue(lines)


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
