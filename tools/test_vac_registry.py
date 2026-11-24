import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import importlib

core = importlib.import_module("vac_core")
registry = importlib.import_module("vac_rules")
ROOT = Path(__file__).resolve().parent.parent


def rule(rule_id="X-1", check=lambda ctx: [], stages=frozenset({"t0"}), watches=("a/**",), needs=(), refs=(1,),
         fix="run x", title="A rule"):
    return core.Rule(rule_id, title, stages, watches, check, fix, refs, needs)


def failing(rule_id):
    return lambda ctx: [core.Finding(rule_id, "a/b", 3, "broken")]


class RunnerTests(unittest.TestCase):
    def test_pass_fail_and_missing_set_the_exit_code(self):
        ok = core.run((rule(),), "t0", core.Ctx())
        self.assertEqual((ok[0].status, core.exit_code(ok)), ("PASS", core.EXIT_PASS))
        bad = core.run((rule("X-2", failing("X-2")),), "t0", core.Ctx())
        self.assertEqual((bad[0].status, core.exit_code(bad)), ("FAIL", core.EXIT_FAIL))
        gone = core.run((rule(needs=("no-such-tool-vac",)),), "t0", core.Ctx())
        self.assertEqual((gone[0].status, core.exit_code(gone)), ("MISSING", core.EXIT_MISSING))

    def test_a_failure_outranks_a_missing_tool(self):
        out = core.run((rule(needs=("no-such-tool-vac",)), rule("X-2", failing("X-2"))), "t0", core.Ctx())
        self.assertEqual(core.exit_code(out), core.EXIT_FAIL)

    def test_a_missing_tool_is_never_a_pass(self):
        out = core.run((rule(needs=("no-such-tool-vac",), stages=frozenset({"t1"})),), "t1", core.Ctx())
        self.assertNotEqual(core.exit_code(out), core.EXIT_PASS)
        self.assertEqual(core.tier(out, "t1"), "T0")

    def test_only_rules_of_the_stage_run(self):
        out = core.run((rule(stages=frozenset({"rc"})),), "t0", core.Ctx())
        self.assertEqual(out, [])

    def test_changed_paths_select_rules_by_watch(self):
        ctx = core.Ctx(changed=("b/c.py",))
        self.assertEqual(core.run((rule(watches=("a/**",)),), "t0", ctx), [])
        self.assertEqual(len(core.run((rule(watches=("b/**",)),), "t0", ctx)), 1)

    def test_tier_is_t1_only_when_every_t1_rule_passed(self):
        passed = core.run((rule(stages=frozenset({"t1"})),), "t1", core.Ctx())
        self.assertEqual(core.tier(passed, "t1"), "T1")
        self.assertEqual(core.tier(passed, "t0"), "T0")
        failed = core.run((rule(stages=frozenset({"t1"}), check=failing("X-1")),), "t1", core.Ctx())
        self.assertEqual(core.tier(failed, "t1"), "T0")
        self.assertEqual(core.tier(passed, "t1", complete=False), "T0")

    def test_a_filtered_t1_run_runs_its_rule_and_never_reports_t1(self):
        child = subprocess.run([sys.executable, str(ROOT / "tools/vac.py"), "check", "--t1", "--rule", "FV-PIN", "--json"],
                               cwd=ROOT, capture_output=True, text=True, timeout=300)
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        summary = json.loads(child.stdout.splitlines()[-1])["summary"]
        self.assertEqual((summary["ran"], summary["failed"]), (1, 0))
        self.assertEqual(summary["tier"], "T0")

    def test_a_tool_that_cannot_start_is_a_finding_and_the_run_goes_on(self):
        check = registry.tool_run("X-2", ["./no-such-tool-vac"], "tools")
        out = core.run((rule("X-2", check), rule("X-3")), "t0", core.Ctx())
        self.assertEqual([o.status for o in out], ["FAIL", "PASS"])
        self.assertIn("could not run", out[0].findings[0].message)

    def test_a_tool_that_overruns_its_timeout_is_a_finding(self):
        check = registry.tool_run("X-2", [sys.executable, "-c", "import time; time.sleep(30)"], "tools", 1)
        found = check(core.Ctx())
        self.assertEqual([f.rule for f in found], ["X-2"])
        self.assertIn("did not finish within 1 seconds", found[0].message)

    def test_text_names_the_rule_the_place_and_the_fix(self):
        out = io.StringIO()
        core.render_text(core.run((rule("X-2", failing("X-2"), fix="vac gen"),), "t0", core.Ctx()), "t0", out)
        first = out.getvalue().splitlines()[0]
        self.assertEqual(first, "FAIL X-2 a/b:3 broken | fix: vac gen")
        self.assertTrue(out.getvalue().splitlines()[-1].startswith("vac: fail 1/1"))

    def test_json_lines_end_with_a_summary(self):
        out = io.StringIO()
        core.render_json(core.run((rule("X-2", failing("X-2")),), "t0", core.Ctx()), "t0", out)
        lines = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual(lines[0]["rule"], "X-2")
        self.assertEqual(lines[0]["fix"], "run x")
        self.assertEqual(lines[-1]["summary"]["failed"], 1)


def temp_repo(test):
    tmp = Path(tempfile.mkdtemp())
    test.addCleanup(__import__("shutil").rmtree, tmp)

    def run(*args):
        return subprocess.run(["git", "-C", str(tmp), "-c", "user.name=t", "-c", "user.email=t@t.invalid",
                               "-c", "commit.gpgsign=false", *args],
                              check=True, capture_output=True, text=True, env=core.git_env()).stdout
    run("init", "-q", "-b", "work")
    return tmp, run


class GitWrapperTests(unittest.TestCase):
    def repo(self):
        tmp, run = temp_repo(self)
        (tmp / "a.py").write_text("x = 1\n", encoding="utf-8")
        run("add", "-A")
        run("commit", "-q", "-m", "c")
        return tmp, run

    def test_changed_paths_names_a_non_ascii_path_unquoted(self):
        tmp, run = self.repo()
        (tmp / "tools").mkdir()
        (tmp / "tools/café.py").write_text("x = 1\n", encoding="utf-8")
        run("add", "-A")
        self.assertEqual(core.changed_paths(core.Ctx(root=tmp), "HEAD"), ("tools/café.py",))

    def test_an_inherited_git_dir_never_redirects_the_wrapper(self):
        tmp, _run = self.repo()
        other, _other_run = self.repo()
        with __import__("unittest.mock").mock.patch.dict(
                os.environ, {"GIT_DIR": str(other / ".git"), "GIT_WORK_TREE": str(other)}):
            self.assertEqual(core.git(core.Ctx(root=tmp), "rev-parse", "--show-toplevel").strip(),
                             subprocess.run(["git", "-C", str(tmp), "rev-parse", "--show-toplevel"],
                                            capture_output=True, text=True, env=core.git_env()).stdout.strip())
            self.assertNotIn("GIT_DIR", core.git_env())


class RegistryTests(unittest.TestCase):
    def test_the_committed_registry_is_well_formed(self):
        self.assertEqual(registry.registry_errors(core.Ctx()), [])

    def test_each_registry_flaw_is_reported(self):
        good = rule("GOOD-1")
        cases = {
            "not unique": (good, good),
            "UPPER-CASE": (rule("lower"),),
            "title": (rule("X-1", title=""),),
            "fix": (rule("X-1", fix=" "),),
            "refs": (rule("X-1", refs=()),),
            "stages": (rule("X-1", stages=frozenset({"later"})),),
            "watches": (rule("X-1", watches=()),),
        }
        saved = registry.RULES
        try:
            for needle, rules in cases.items():
                with self.subTest(needle=needle):
                    registry.RULES = rules
                    found = registry.registry_errors(core.Ctx())
                    self.assertTrue(any(needle in f.message for f in found), found)
        finally:
            registry.RULES = saved

    def test_every_claims_rule_number_is_registered(self):
        text = (ROOT / "tools/claims_check.py").read_text(encoding="utf-8")
        documented = {int(n) for n in __import__("re").findall(r"^CI-(\d+)\s", text, __import__("re").M)}
        ids = {r.id for r in registry.RULES}
        self.assertGreaterEqual(len(documented), 10)
        self.assertEqual({n for n in documented if f"CL-{n}" not in ids}, set())


class ClaimMappingTests(unittest.TestCase):
    def ctx_with(self, errors):
        ctx = core.Ctx()
        ctx.memo["claims-report"] = {"errors": errors}
        return ctx

    def test_each_error_lands_on_its_own_rule(self):
        ctx = self.ctx_with(["CI-3 K-1: proved needs a law", "CI-10 results/ci/lab-x: no provenance.json"])
        self.assertEqual([f.rule for f in registry.claim_rule(3)(ctx)], ["CL-3"])
        self.assertEqual([f.rule for f in registry.claim_rule(10)(ctx)], ["CL-10"])
        self.assertEqual(registry.claim_rule(1)(ctx), [])

    def test_an_unregistered_error_is_never_dropped(self):
        ctx = self.ctx_with(["CI-99 new rule", "docs/claims.md is out of date; run tools/claims_check.py --write"])
        self.assertEqual(len(registry.claims_other(ctx)), 2)


class LawKillTests(unittest.TestCase):
    def tree(self, laws, report):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, tmp)
        (tmp / "formal").mkdir()
        (tmp / "results").mkdir()
        (tmp / "formal/LAWS.bend").write_text("".join(f"law {name}:\n  1\n" for name in laws), encoding="utf-8")
        (tmp / "results/mutation-check.json").write_text(json.dumps(report), encoding="utf-8")
        return core.Ctx(root=tmp)

    def test_a_law_no_mutant_breaks_is_reported(self):
        ctx = self.tree(["a", "b"], {"bend": [{"mutant": "m", "laws_violated": ["a"]}]})
        self.assertEqual([f.message.split()[1] for f in registry.laws_without_killer(ctx)], ["b"])

    def test_every_law_broken_passes(self):
        ctx = self.tree(["a"], {"bend": [{"mutant": "m", "laws_violated": ["a"]}]})
        self.assertEqual(registry.laws_without_killer(ctx), [])


class RustRuleTests(unittest.TestCase):
    def tree(self, cargo):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, tmp)
        (tmp / "Cargo.toml").write_text(cargo, encoding="utf-8")
        return core.Ctx(root=tmp)

    def test_release_must_abort_on_panic(self):
        self.assertEqual(registry.panic_aborts(self.tree('[profile.release]\npanic = "abort"\n')), [])
        self.assertEqual([f.rule for f in registry.panic_aborts(self.tree('[profile.release]\npanic = "unwind"\n'))],
                         ["RS-PANIC"])
        self.assertEqual([f.rule for f in registry.panic_aborts(self.tree(""))], ["RS-PANIC"])

    def test_allow_attributes_are_counted_inner_and_outer(self):
        files = {"a.rs": "#[allow(x)]\n#![allow(y)]\n# [ allow (z)]\n", "b.rs": "#[deny(x)]\nallow\n"}
        self.assertEqual(registry.allow_count(files.get, ["a.rs", "b.rs", "gone.rs"]), 3)
        self.assertEqual(registry.allow_lints("#[allow(a, b)]\n#[allow(clippy::c)]\n"), ["a", "b", "clippy::c"])

    def added(self, base, head):
        paths = sorted(set(base) | set(head))
        return registry.allow_added(registry.allow_places(base.get, paths),
                                    registry.allow_places(head.get, paths))

    def test_an_allow_that_moves_file_or_lint_is_still_an_addition(self):
        base = {"crates/a.rs": "#[allow(dead_code)]\nfn a() {}\n", "crates/b.rs": "fn b() {}\n"}
        self.assertEqual(self.added(base, base), [])
        self.assertEqual(self.added(base, {"crates/a.rs": "fn a() {}\n",
                                           "crates/b.rs": "#[allow(dead_code)]\nfn b() {}\n"}),
                         [("crates/b.rs", "dead_code")])
        self.assertEqual(self.added(base, {"crates/a.rs": "#[allow(unused)]\nfn a() {}\n",
                                           "crates/b.rs": "fn b() {}\n"}),
                         [("crates/a.rs", "unused")])
        self.assertEqual(self.added(base, {"crates/a.rs": "#[allow(dead_code)]\n#[allow(dead_code)]\nfn a() {}\n",
                                           "crates/b.rs": "fn b() {}\n"}),
                         [("crates/a.rs", "dead_code")])

    def test_removing_an_allow_is_accepted(self):
        base = {"crates/a.rs": "#[allow(dead_code)]\nfn a() {}\n"}
        self.assertEqual(self.added(base, {"crates/a.rs": "fn a() {}\n"}), [])
        self.assertEqual(self.added(base, {}), [])


class LineEndingTests(unittest.TestCase):
    def test_a_mixed_or_crlf_file_is_refused_unless_it_is_a_cmd(self):
        tmp, run = temp_repo(self)
        run("config", "core.autocrlf", "false")
        (tmp / ".gitattributes").write_text("* -text\n", encoding="utf-8")
        (tmp / "mixed.sh").write_bytes(b"a\r\nb\n")
        (tmp / "crlf.sh").write_bytes(b"a\r\nb\r\n")
        (tmp / "ok.cmd").write_bytes(b"a\r\nb\r\n")
        (tmp / "lf.sh").write_bytes(b"a\nb\n")
        run("add", "-A")
        run("commit", "-q", "-m", "c")
        found = registry.line_endings(core.Ctx(root=tmp))
        self.assertEqual(sorted((f.path, f.message.split(";")[0]) for f in found),
                         [("crlf.sh", "committed with crlf line endings"),
                          ("mixed.sh", "committed with mixed line endings")])


class WaiverRowTests(unittest.TestCase):
    def repo(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, tmp)
        run = lambda *a: subprocess.run(["git", "-C", str(tmp), *a], check=True, capture_output=True, text=True,
                                        env=core.git_env()).stdout
        run("init", "-q")
        (tmp / "f").write_text("x", encoding="utf-8")
        run("add", "f")
        run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "x")
        return tmp, run("rev-parse", "HEAD").strip()

    def receipt(self, root, head, reason="r", ok=True):
        body = {"base": "b" * 40, "head": head, "ok": ok, "waivable": [reason], "steps": []}
        digest = __import__("hashlib").sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        (root / "ci/waiver-receipts").mkdir(parents=True, exist_ok=True)
        (root / f"ci/waiver-receipts/{digest}.json").write_text(json.dumps({**body, "digest": digest}), encoding="utf-8")
        return digest

    def check(self, root, rows, waivable=("r",)):
        text = __import__("vac_safety").waiver_toml(rows)
        ctx = core.Ctx(root=root, base="b" * 40)
        def head_get(path):
            if path == "ci/waivers.toml":
                return text
            found = root / path
            return found.read_text(encoding="utf-8") if found.exists() else None
        ctx.memo["escalations"] = ([], list(waivable), lambda p: None, head_get)
        return [f.message for f in registry.waivers_cover(ctx)]

    def test_a_row_naming_another_head_than_its_receipt_is_refused(self):
        root, head = self.repo()
        digest = self.receipt(root, "c" * 40)
        found = self.check(root, [{"reason": "r", "issue": 1, "receipt": digest, "head": head}])
        self.assertEqual(len(found), 1)
        self.assertIn("its receipt ran at", found[0])

    def test_a_receipt_that_is_not_a_json_object_is_a_finding_not_a_crash(self):
        root, head = self.repo()
        (root / "ci/waiver-receipts").mkdir(parents=True, exist_ok=True)
        for name, body in (("a" * 64, "{truncated"), ("b" * 64, "[]")):
            (root / f"ci/waiver-receipts/{name}.json").write_text(body, encoding="utf-8")
            found = self.check(root, [{"reason": "r", "issue": 1, "receipt": name, "head": head}])
            self.assertEqual(len(found), 1, found)
            self.assertIn("not a JSON object", found[0])

    def test_a_receipt_judged_from_another_base_is_refused(self):
        root, head = self.repo()
        digest = self.receipt(root, head)
        receipt = root / f"ci/waiver-receipts/{digest}.json"
        data = json.loads(receipt.read_text(encoding="utf-8"))
        body = {k: v for k, v in data.items() if k != "digest"}
        body["base"] = "c" * 40
        digest = __import__("hashlib").sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        (root / f"ci/waiver-receipts/{digest}.json").write_text(json.dumps({**body, "digest": digest}), encoding="utf-8")
        found = self.check(root, [{"reason": "r", "issue": 1, "receipt": digest, "head": head}])
        self.assertEqual(len(found), 1, found)
        self.assertIn("judged from base", found[0])

    def test_a_newer_row_supersedes_an_obsolete_one_for_the_same_reason(self):
        root, head = self.repo()
        old = self.receipt(root, "c" * 40)
        new = self.receipt(root, head)
        rows = [{"reason": "r", "issue": 1, "receipt": old, "head": "c" * 40},
                {"reason": "r", "issue": 1, "receipt": new, "head": head}]
        self.assertEqual(self.check(root, rows), [])
        self.assertEqual(len(self.check(root, rows[:1])), 1)


class CommandTests(unittest.TestCase):
    def vac(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "tools/vac.py"), *args], cwd=ROOT, capture_output=True,
                              text=True, timeout=300)

    def test_rules_lists_every_registered_rule(self):
        child = self.vac("rules")
        self.assertEqual(child.returncode, 0, child.stderr)
        listed = [line.split("\t")[0] for line in child.stdout.splitlines()]
        self.assertEqual(listed, [r.id for r in registry.RULES])

    def test_explain_a_path_names_the_rules_watching_it(self):
        child = self.vac("explain", "crates/containment-host/Cargo.toml")
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertIn("POL-SAB:", child.stdout)
        self.assertIn("fix:", child.stdout)

    def test_an_unknown_rule_is_a_usage_error(self):
        child = self.vac("check", "--rule", "NO-SUCH-RULE")
        self.assertEqual(child.returncode, core.EXIT_USAGE)

    def test_a_rule_that_cannot_run_at_this_stage_is_a_usage_error(self):
        child = self.vac("check", "--rule", "FV-SYNC", "--json")
        self.assertEqual(child.returncode, core.EXIT_USAGE, child.stdout + child.stderr)
        self.assertIn("FV-SYNC does not run at stage t0", child.stderr)
        self.assertIn("rc, release", child.stderr)
        self.assertEqual(child.stdout, "")
        ran = self.vac("check", "--stage", "rc", "--rule", "FV-SYNC", "--json")
        self.assertEqual(json.loads(ran.stdout.splitlines()[-1])["summary"]["ran"], 1)

    def test_verify_record_refuses_any_uncommitted_change(self):
        target = ROOT / "Cargo.toml"
        original = target.read_bytes()
        try:
            target.write_bytes(original + b"\n")
            child = self.vac("verify", "record")
        finally:
            target.write_bytes(original)
        self.assertEqual(child.returncode, core.EXIT_USAGE, child.stdout + child.stderr)
        self.assertIn("commit every change first", child.stderr)

    def test_one_rule_runs_and_passes(self):
        child = self.vac("check", "--rule", "POL-SAB", "--json")
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        self.assertEqual(json.loads(child.stdout.splitlines()[-1])["summary"]["ran"], 1)


class GenTests(unittest.TestCase):
    def test_agents_lists_every_rule_and_every_gap(self):
        gen = importlib.import_module("vac_gen")
        text = gen.render_agents(registry.RULES, registry.UNENFORCED)
        for r in registry.RULES:
            self.assertIn(f"| {r.id} |", text)
        rows = {line.split("|")[1].strip(): line for line in text.splitlines() if line.startswith("| ")}
        for rule_id, _title, issue in registry.UNENFORCED:
            self.assertTrue(rows[rule_id].rstrip().endswith(f"| #{issue} |"), rows[rule_id])
        self.assertEqual(gen.render_claude(), "@AGENTS.md\n")

    def test_an_unenforced_id_never_shadows_an_enforced_one(self):
        self.assertEqual({r.id for r in registry.RULES} & {u[0] for u in registry.UNENFORCED}, set())

    def test_generated_files_in_the_tree_match(self):
        self.assertEqual(registry.generated_files_match(core.Ctx()), [])

    def test_a_crlf_copy_of_a_generated_file_is_drift(self):
        gen = importlib.import_module("vac_gen")
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, tmp)
        for path, text in gen.generated(registry.RULES, registry.UNENFORCED).items():
            (tmp / path).write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
        found = registry.generated_files_match(core.Ctx(root=tmp))
        self.assertEqual(sorted(f.path for f in found), ["AGENTS.md", "CLAUDE.md"])

    def test_the_generated_guide_says_which_stage_the_default_runs(self):
        gen = importlib.import_module("vac_gen")
        intro = gen.render_agents(registry.RULES, registry.UNENFORCED).split("## ")[0]
        self.assertIn("`t0`", intro)
        self.assertIn("--t1", intro)
        self.assertIn("--stage", intro)

    def test_a_decision_record_is_refused(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, tmp)
        (tmp / "docs/decisions").mkdir(parents=True)
        (tmp / "docs/decisions/0001-x.md").write_text("x", encoding="utf-8")
        self.assertEqual([f.rule for f in registry.no_decision_records(core.Ctx(root=tmp))], ["DEC-1"])


if __name__ == "__main__":
    unittest.main()
