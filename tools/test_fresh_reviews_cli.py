#!/usr/bin/env python3
"""Unit tests for `policy_check.py fresh-reviews` as a command (#149).

The corpus runner and the workflows call it as a child process. It prints the reviews
as one JSON list on stdout and nothing else. It refuses input that is not the API's
JSON shape by exiting 1, with no traceback and a last stderr line starting
"fresh-reviews: ". An arrival it cannot establish is not a refusal: it voids every
review and exits 0, so that a lane A change is never stopped by the push log."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
CHECKER = TOOLS / "policy_check.py"
HEAD = "1" * 40
BASE = "2" * 40


def corpus_files(case, tmp, change=None):
    """The case's inputs with @HEAD@ and @BASE@ filled in, written to tmp, as
    {name: path}. `change` may rewrite the parsed inputs first."""
    folder = ROOT / "ci/corpus/approval" / case / "inputs"
    data = {p.stem: json.loads(p.read_text(encoding="utf-8").replace("@HEAD@", HEAD).replace("@BASE@", BASE))
            for p in folder.glob("*.json")}
    if change:
        change(data)
    out = {}
    for name, value in data.items():
        out[name] = Path(tmp) / f"{name}.json"
        out[name].write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
    return out


def run(files, head=HEAD, extra=()):
    argv = [sys.executable, "-I", "-B", str(CHECKER), "fresh-reviews"]
    if head is not None:
        argv += ["--head-sha", head]
    for name, path in files.items():
        argv += [f"--{name}", str(path)]
    return subprocess.run(argv + list(extra), cwd=ROOT, capture_output=True, text=True, timeout=60)


class Output(unittest.TestCase):
    def test_93_keeps_its_review_with_no_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            child = run(corpus_files("carried-over-93", tmp))
        self.assertEqual(child.returncode, 0, child.stderr)
        kept = json.loads(child.stdout)
        self.assertEqual([(r["state"], r["commit_id"]) for r in kept], [("APPROVED", None)])

    def test_147_keeps_its_review_as_it_was(self):
        with tempfile.TemporaryDirectory() as tmp:
            child = run(corpus_files("fresh-after-push-147", tmp))
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual([r["commit_id"] for r in json.loads(child.stdout)], [HEAD])
        self.assertEqual(child.stderr, "")

    def test_an_unknown_arrival_voids_every_review_without_refusing(self):
        def lag(data):
            data["activity"][0]["after"] = BASE
        with tempfile.TemporaryDirectory() as tmp:
            child = run(corpus_files("fresh-after-push-147", tmp, lag))
        self.assertEqual(child.returncode, 0)
        self.assertEqual([r["commit_id"] for r in json.loads(child.stdout)], [None])
        self.assertIn("voided every review", child.stderr)
        self.assertFalse(child.stderr.strip().splitlines()[-1].startswith("fresh-reviews: "))

    def test_the_output_feeds_classify(self):
        # The shape classify --reviews reads: a flat list it can pass to approved().
        with tempfile.TemporaryDirectory() as tmp:
            child = run(corpus_files("fresh-after-push-147", tmp, lambda d: d.update(reviews=[d["reviews"]])))
        self.assertIsInstance(json.loads(child.stdout)[0], dict)


class Refusals(unittest.TestCase):
    def assertRefuses(self, child, reason):
        self.assertEqual(child.returncode, 1, child.stdout + child.stderr)
        self.assertNotIn("Traceback", child.stderr)
        self.assertEqual(child.stdout, "")
        last = child.stderr.strip().splitlines()[-1]
        self.assertTrue(last.startswith("fresh-reviews: "), last)
        self.assertIn(reason, last)

    def test_a_missing_input_is_refused(self):
        for name in ("reviews", "activity", "pr", "timeline"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                files = corpus_files("fresh-after-push-147", tmp)
                del files[name]
                self.assertRefuses(run(files), f"--{name} is required")

    def test_a_missing_or_bad_head_sha_is_refused(self):
        for head in (None, "", "abc", "A" * 40, HEAD + "0", " " + HEAD):
            with self.subTest(head=head), tempfile.TemporaryDirectory() as tmp:
                self.assertRefuses(run(corpus_files("fresh-after-push-147", tmp), head=head), "--head-sha")

    def test_an_unreadable_input_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = corpus_files("fresh-after-push-147", tmp, lambda d: d.update(activity="[{"))
            self.assertRefuses(run(files), "--activity")
            files = corpus_files("fresh-after-push-147", tmp)
            files["timeline"] = Path(tmp) / "nowhere.json"
            self.assertRefuses(run(files), "--timeline")

    def test_input_of_the_wrong_shape_is_refused(self):
        for name, value in (("reviews", {}), ("reviews", ["x"]), ("reviews", [[["deep"]]]), ("activity", {}),
                            ("pr", []), ("timeline", [1]), ("reviews", None)):
            with self.subTest(name=name, value=value), tempfile.TemporaryDirectory() as tmp:
                files = corpus_files("fresh-after-push-147", tmp, lambda d: d.update({name: value}))
                self.assertRefuses(run(files), f"--{name}")

    def test_an_unknown_option_is_an_argparse_error_not_a_refusal(self):
        # The runner never counts exit 2 as a refusal; this keeps the two apart.
        with tempfile.TemporaryDirectory() as tmp:
            child = run(corpus_files("fresh-after-push-147", tmp), extra=["--extra", "x"])
        self.assertEqual(child.returncode, 2)


if __name__ == "__main__":
    unittest.main()
