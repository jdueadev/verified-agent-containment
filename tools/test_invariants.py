"""Run the seeded cases in tools/invariant_cases against invariants_check."""
import shutil
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import invariants_check  # noqa: E402

ROOT = HERE.parent
CASES = sorted(p for p in (HERE / "invariant_cases").iterdir() if p.is_dir())


class SeededCases(unittest.TestCase):
    def test_there_are_cases(self):
        self.assertGreaterEqual(len(CASES), 6)

    def test_each_case_is_judged_as_expected(self):
        for case in CASES:
            with self.subTest(case=case.name), tempfile.TemporaryDirectory() as tmp:
                spec = tomllib.loads((case / "case.toml").read_text())
                tree = Path(tmp)
                # A case is the real checkout's host manifest and the host and kernel
                # sources, with the case's own files laid over them.
                manifest = tree / invariants_check.HOST_MANIFEST
                manifest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(ROOT / invariants_check.HOST_MANIFEST, manifest)
                for src in (invariants_check.HOST_SRC, invariants_check.KERNEL_SRC, "formal/kani"):
                    shutil.copytree(ROOT / src, tree / src, ignore=shutil.ignore_patterns("*.html"))
                if (case / "tree").is_dir():
                    shutil.copytree(case / "tree", tree, dirs_exist_ok=True)
                # A `[[replace]]` edits a real source in place; its `old` text must be
                # there exactly once, so a case cannot go quietly stale.
                for edit in spec.get("replace", []):
                    target = tree / edit["file"]
                    text = target.read_text(encoding="utf-8")
                    self.assertEqual(text.count(edit["old"]), 1, (edit["file"], edit["old"]))
                    target.write_text(text.replace(edit["old"], edit["new"]), encoding="utf-8")
                found = invariants_check.errors(tree)
                if spec["expect"] == "accept":
                    self.assertEqual(found, [])
                else:
                    self.assertTrue(found)
                    if "expect_error" in spec:
                        self.assertTrue(any(spec["expect_error"] in line for line in found), found)

    def test_the_checkout_itself_passes(self):
        self.assertEqual(invariants_check.errors(ROOT), [])


class HostCfgConditions(unittest.TestCase):
    """#121: the host's build conditions are a closed list."""
    GATEWAY = f"{invariants_check.HOST_SRC}/controller/gateway.rs"
    WEAKNESS = f"{invariants_check.HOST_SRC}/controller/weakness.rs"
    COMMON = f"{invariants_check.HOST_SRC}/common.rs"

    def check(self, src, path=GATEWAY):
        return invariants_check.host_cfg_errors({path: src})

    def refused(self, src, needle, path=GATEWAY):
        found = self.check(src, path)
        self.assertTrue(any(needle in line for line in found), found)

    def test_the_allowed_list_passes(self):
        for src in ("#[cfg(test)] mod t {}",
                    "#![cfg(not(kani))]",
                    '#[cfg(target_arch = "x86_64")] fn f() {}',
                    '#[cfg(all(not(test), any(target_arch = "x86_64", target_arch = "aarch64",)))] fn f() {}',
                    "#[cfg_attr(test, derive(Debug))] struct S;",
                    'let x = cfg!(target_arch = "x86_64");'):
            with self.subTest(src=src):
                self.assertEqual(self.check(src), [])

    def test_sabotage_is_allowed_in_the_registry_and_on_test_items(self):
        self.assertEqual(self.check('#[cfg(feature = "sabotage")] struct Weakness;', self.WEAKNESS), [])
        self.assertEqual(self.check('pub const B: bool = cfg!(feature = "sabotage");', self.COMMON), [])
        self.assertEqual(self.check('#[cfg(feature = "sabotage")]\n#[test]\nfn t() {}'), [])
        self.assertEqual(self.check('#[test]\n#[cfg(feature = "sabotage")]\nfn t() {}'), [])

    def test_sabotage_elsewhere_is_refused_and_names_the_fix(self):
        for src in ('#[cfg(feature = "sabotage")] fn skip() {}',
                    'const ON: bool = cfg!(feature = "sabotage");',
                    '#[cfg(feature = "sabotage")]\n#[inline]\nfn skip() {}',
                    '#[cfg(feature = "sabotage")] fn skip() {}\n#[test] fn later() {}'):
            with self.subTest(src=src):
                self.refused(src, "add the defect to `weaknesses!` in `controller/weakness.rs`")

    def test_debug_assertions_and_other_features_are_refused(self):
        self.refused("#[cfg(debug_assertions)] fn f() {}", "`debug_assertions` is not an allowed")
        self.refused('#[cfg(feature = "fast")] fn f() {}', '`feature = "fast"` is not an allowed')
        self.refused('#[cfg(target_os = "linux")] fn f() {}', '`target_os = "linux"` is not an allowed')
        self.refused("#[cfg(miri)] fn f() {}", "`miri` is not an allowed")

    def test_cfg_attr_path_is_refused(self):
        self.refused('#[cfg_attr(test, path = "x.rs")] mod m;', "`cfg_attr(.., path = ..)`")
        self.refused('#[cfg_attr(test, inline, path = "x.rs")] mod m;', "`cfg_attr(.., path = ..)`")

    def test_nesting_cannot_hide_a_condition(self):
        self.refused("#[cfg(any(test, all(not(test), debug_assertions)))] fn f() {}", "`debug_assertions`")
        self.refused("#[cfg_attr(debug_assertions, inline)] fn f() {}", "`debug_assertions`")
        self.refused("#[cfg_attr(test, cfg(debug_assertions))] fn f() {}", "`debug_assertions`")
        self.refused('#[cfg_attr(test, cfg_attr(test, path = "x.rs"))] mod m;', "`cfg_attr(.., path = ..)`")

    def test_raw_strings_and_raw_identifiers_are_normalised(self):
        for src in ('#[cfg(feature = r"sabotage")] fn f() {}',
                    '#[cfg(feature = r#"sabotage"#)] fn f() {}',
                    '#[r#cfg(feature = "sabotage")] fn f() {}',
                    'const ON: bool = r#cfg!(feature = r##"sabotage"##);'):
            with self.subTest(src=src):
                self.refused(src, '`feature = "sabotage"` is allowed only')
        self.assertEqual(self.check('#[cfg(feature = r#"sabotage"#)] struct W;', self.WEAKNESS), [])

    def test_escaped_names_are_refused(self):
        self.refused('#[cfg(feature = "sab\\x6ftage")] fn f() {}', "cannot read")

    def test_comments_docs_and_strings_do_not_count(self):
        src = ('// #[cfg(debug_assertions)]\n/* cfg!(feature = "fast") */\n'
               '/// #[cfg(debug_assertions)]\nconst S: &str = "#[cfg(debug_assertions)]";\n')
        self.assertEqual(self.check(src), [])

    def test_unreadable_uses_are_refused(self):
        self.refused("let cfg = 1;", "form the check cannot read")
        self.refused("#[cfg(test, test)] fn f() {}", "exactly one predicate")
        self.refused("#[cfg($p)] fn f() {}", "is not an allowed build condition")
        self.refused('const S: &str = "', "cannot be read")

    def test_the_real_host_passes(self):
        host = ROOT / invariants_check.HOST_SRC
        files = {p.relative_to(ROOT).as_posix(): p.read_text(encoding="utf-8") for p in host.rglob("*.rs")}
        self.assertIn(self.WEAKNESS, files)
        self.assertEqual(invariants_check.host_cfg_errors(files), [])


class HostEvents(unittest.TestCase):
    """#120: each controller handler builds only its channel's kernel events."""
    H = invariants_check.HOST_SRC
    RESET = f"{H}/controller/reset.rs"
    CLASSIFIER = f"{H}/controller/classifier.rs"
    CONTROLLER = f"{H}/controller.rs"
    DEFECT = f"{H}/controller/defect.rs"

    @classmethod
    def setUpClass(cls):
        cls.real = {p.relative_to(ROOT).as_posix(): p.read_text(encoding="utf-8")
                    for p in (ROOT / cls.H).rglob("*.rs")}
        for target in invariants_check.event_path_targets(cls.real):
            cls.real[target] = (ROOT / target).read_text(encoding="utf-8")

    def check(self, path=None, old=None, new=None, add=None):
        files = dict(self.real)
        if old is not None:
            self.assertEqual(files[path].count(old), 1, old)
            files[path] = files[path].replace(old, new)
        files.update(add or {})
        return invariants_check.host_event_errors(files)

    def refused(self, needle, *args, **kwargs):
        found = self.check(*args, **kwargs)
        self.assertTrue(any(needle in line for line in found), found)

    def test_the_real_host_passes_and_reads_the_kani_proofs(self):
        self.assertIn("formal/kani/gate_proofs.rs", self.real)
        self.assertEqual(self.check(), [])

    def test_a_variant_outside_its_handler_is_refused(self):
        self.refused("`control_handler` may name only HardRule, Tick, not `Event::Renew`", self.RESET,
                     "let _ = shared.apply(None, received, |now_ms| Event::Tick { now_ms });",
                     "let _ = shared.apply(None, received, |now_ms| Event::Renew { now_ms, ttl_ms: 0 });")
        self.refused("`monitor_handler` may name only Renew, not `Event::Reset`", self.RESET,
                     "Event::Renew { now_ms, ttl_ms }", "Event::Reset { now_ms, ttl_ms }")

    def test_group_imports_and_unreadable_paths_are_refused(self):
        for src, needle in (("use containment_kernel::Event::{Renew};", "by glob or group"),
                            ("use containment_kernel::{Event as E};", "renames `Event`"),
                            ("macro_rules! m { ($v:ident) => { Event::$v { now_ms: 0 } } }", "`Event::$` is not a variant"),
                            ("fn f() { let _ = Event::renew(0); }", "`Event::renew` is not a variant"),
                            ('include!("other.rs");', "`include!` brings in source")):
            with self.subTest(src=src):
                self.refused(needle, add={self.DEFECT: src})

    def test_a_match_pattern_is_not_a_build(self):
        self.refused("`Shared::apply` may name only HardRule, Reset{..}, not `Event::Reset`", self.CONTROLLER,
                     "matches!(event, Event::Reset { .. })", "matches!(event, Event::Reset { now_ms: 0, ..x })")
        self.refused("`event_name` may name only", self.CONTROLLER,
                     'Event::Tick { .. } => "lease_clock"', 'Event::Tick { now_ms: 0 } => "lease_clock"')

    def test_the_classifier_side_never_names_other_channels_variants(self):
        system_one = f"{self.H}/system_one.rs"
        self.refused("names `Reset`, which the classifier's side may never name",
                     add={system_one: self.real[system_one] + "\nenum Op { Reset }\n"})
        self.refused("names `Renew`, which the classifier's side may never name", self.CLASSIFIER,
                     "Event::Classifier { now_ms, level } }", "Event::Renew { now_ms, ttl_ms: 0 } }")

    def test_the_sabotage_exception_is_exact(self):
        pinned = "`classifier_uncapped` in `apply_classifier` is no longer its pinned gated branch"
        binding = "let uncapped = shared.weak.classifier_uncapped();"
        self.refused(pinned, self.CLASSIFIER, binding, binding + "\n    let uncapped = true;")
        self.refused(pinned, self.CLASSIFIER, binding, "let uncapped = shared.weak.excerpt_uncapped();")
        # A second, ungated hard rule beside the pinned branch is refused on its own.
        self.refused("names `Event::HardRule` in `read_verdicts`", self.CLASSIFIER,
                     "apply_classifier(shared, Some(label), now, level);\n        }",
                     "shared.apply(None, now, |now_ms| Event::HardRule { now_ms, level });\n        }")

    def test_helpers_and_handlers_are_called_only_from_their_channel(self):
        self.refused("names `admit`, which builds events for another channel", self.RESET,
                     "let ttl_ms = message[", "let _ = shared.admit;\n    let ttl_ms = message[")
        self.refused("`monitor_handler` appears 3 times", self.RESET,
                     'Some("status") => {}', 'Some("status") => { monitor_handler(shared, message.clone(), peer); }')
        self.refused("names `differential`, whose events never reach a controller", self.RESET,
                     'Some("status") => {}', 'Some("status") => { let _ = crate::differential::run(&[]); }')
        self.refused("names `differential`, whose events never reach a controller", self.CONTROLLER,
                     "crate::kernel_trace::kernel_line(", "crate::differential::kernel_line(")

    def test_the_trace_encoder_may_only_match_events(self):
        trace = f"{self.H}/kernel_trace.rs"
        arm = 'Event::Tick { now_ms } => json!({"type":"tick","now":now_ms}),'
        for src, why in (('_ if now_ms == 0 => { let _ = Event::Tick { now_ms: 0 }; json!({}) }', "a value in an arm body"),
                         ('e if e == Event::Tick { now_ms: 0 } => json!({}),', "a value in a guard"),
                         ('_ => json!(Event::Tick { now_ms: 0 }.now_ms()),', "a value after `=>`")):
            with self.subTest(why=why):
                self.refused("`encode` may name `Event::Tick` only as a match-arm pattern", trace, arm, arm + "\n        " + src)
        self.refused("names `Event::Tick` in `control_json`, which the event table does not list", trace,
                     "pub fn control_json(control: Control) -> Value {",
                     "pub fn control_json(control: Control) -> Value {\n    let _ = Event::Tick { now_ms: 0 };")
        self.refused("the pattern table lists `encode`, which is not exactly one function here", trace,
                     "pub fn encode(event: Event)", "pub fn encode_event(event: Event)")

    def test_a_renamed_table_function_is_refused(self):
        self.refused("lists `monitor_handler`, which is not exactly one function here", self.RESET,
                     "fn monitor_handler(", "fn monitor_handler_v2(")

    def test_a_lookalike_enum_is_exempt_only_by_name(self):
        run_live = f"{self.H}/run_live.rs"
        self.refused("names `Event::Reset` in", run_live, "CtlAction::Reset { mode }", "Reset { mode }")

    def test_unreadable_sources_are_refused(self):
        self.refused("cannot be read", add={self.DEFECT: 'const S: &str = "'})
        self.refused("unbalanced delimiters", add={self.DEFECT: "fn f() {"})

class HostManifest(unittest.TestCase):
    """#121: the host's features are exactly default and sabotage, with no build script."""
    REAL = (ROOT / invariants_check.HOST_MANIFEST).read_text(encoding="utf-8")

    def test_the_real_manifest_passes(self):
        self.assertEqual(invariants_check.host_manifest_errors(self.REAL, False), [])
        self.assertFalse((ROOT / invariants_check.HOST_CRATE / "build.rs").exists())

    def test_another_feature_is_refused(self):
        for text in (self.REAL.replace("sabotage = []", "sabotage = []\nfast = []"),
                     self.REAL.replace("sabotage = []", 'sabotage = ["dep:libc"]'),
                     self.REAL.replace("default = []", 'default = ["std"]\nstd = []')):
            with self.subTest(text=text):
                self.assertNotEqual(text, self.REAL)
                self.assertTrue(invariants_check.host_manifest_errors(text, False))

    def test_a_build_script_is_refused(self):
        self.assertTrue(invariants_check.host_manifest_errors(self.REAL, True))
        moved = self.REAL.replace("license.workspace = true", 'license.workspace = true\nbuild = "gen.rs"')
        self.assertNotEqual(moved, self.REAL)
        self.assertTrue(invariants_check.host_manifest_errors(moved, False))


if __name__ == "__main__":
    unittest.main()
