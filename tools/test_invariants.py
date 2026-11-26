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
                for src in (invariants_check.HOST_SRC, invariants_check.KERNEL_SRC):
                    shutil.copytree(ROOT / src, tree / src, ignore=shutil.ignore_patterns("*.html"))
                shutil.copytree(case / "tree", tree, dirs_exist_ok=True)
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
