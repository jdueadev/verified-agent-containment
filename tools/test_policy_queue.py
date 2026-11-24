#!/usr/bin/env python3
import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import policy_check as pc
from test_policy_check import CLAIMS, ROOT


class QueueTests(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "t")
        self.git("config", "user.email", "t@example.invalid")
        self.write("ci/lanes.toml", (ROOT / "ci/lanes.toml").read_text(encoding="utf-8"))
        self.write("docs/reference.md", "base\n")
        self.write("AGENTS.md", "rules\n")
        self.write("claims.toml", CLAIMS)
        self.base = self.commit("base")
        self.prs = 0
        for name in ("git", "git_bytes"):
            patcher = mock.patch.object(pc, name, getattr(self, name))
            patcher.start()
            self.addCleanup(patcher.stop)

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.tmp), *args], capture_output=True, text=True,
                              encoding="utf-8", check=True).stdout

    def git_bytes(self, *args):
        return subprocess.run(["git", "-C", str(self.tmp), *args], capture_output=True, check=True).stdout

    def write(self, path, text):
        target = self.tmp / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD").strip()

    def pr(self, files):
        self.prs += 1
        self.git("checkout", "-q", "-b", f"pr{self.prs}", self.base)
        for path, text in files.items():
            self.write(path, text)
        head = self.commit(f"pr {self.prs}")
        self.git("checkout", "-q", "main")
        return head

    def land(self, previous, head, tree=None):
        if tree is None:
            tree = self.git("merge-tree", "--write-tree", previous, head).split()[0]
        return self.git("commit-tree", tree, "-p", previous, "-m", "queued").strip()

    def entry(self, number, head, group_commit, approved_at=None, fork=False):
        reviews = [{"user": {"login": "jdueadev"}, "state": "APPROVED", "commit_id": approved_at}] if approved_at else []
        return {"number": number, "head_sha": head, "group_commit": group_commit, "fork": fork, "reviews": reviews}

    def group(self, *heads):
        commits, previous = [], self.base
        for head in heads:
            previous = self.land(previous, head)
            commits.append(previous)
        return commits

    def test_a_head_with_two_best_common_ancestors_lands_as_git_merges_it(self):
        self.write("f.md", "a\n")
        self.write("g.md", "a\n")
        self.base = start = self.commit("f and g")
        x1 = self.pr({"f.md": "b\n"})
        y1 = self.pr({"g.md": "b\n"})
        both = self.git("merge-tree", "--write-tree", x1, y1).split()[0]
        x2 = self.git("commit-tree", both, "-p", x1, "-p", y1, "-m", "x2").strip()
        y2 = self.git("commit-tree", both, "-p", y1, "-p", x1, "-m", "y2").strip()
        tip = self.git("commit-tree", f"{start}^{{tree}}", "-p", x2, "-m", "main undoes f and g").strip()
        self.git("checkout", "-q", "-b", "criss-cross", y2)
        self.write("docs/reference.md", "changed\n")
        head = self.commit("pr")
        self.git("checkout", "-q", "main")
        self.assertEqual(len(self.git("merge-base", "--all", tip, head).split()), 2)
        group = self.land(tip, head)
        rows, problems = pc.judge_queue(tip, group, [self.entry(1, head, group)])
        self.assertEqual(problems, [])
        self.assertEqual([r["lane"] for r in rows], ["A"])

    def test_a_lane_a_change_and_an_approved_lane_c_change_pass(self):
        a = self.pr({"docs/reference.md": "changed\n"})
        c = self.pr({"AGENTS.md": "rules, changed\n"})
        ga, gc = self.group(a, c)
        rows, problems = pc.judge_queue(self.base, gc, [self.entry(1, a, ga), self.entry(2, c, gc, approved_at=c)])
        self.assertEqual(problems, [])
        self.assertEqual([r["lane"] for r in rows], ["A", "C"])

    def test_an_unapproved_or_stale_approved_lane_c_member_fails(self):
        c = self.pr({"AGENTS.md": "rules, changed\n"})
        (gc,) = self.group(c)
        for approved_at in (None, self.base):
            with self.subTest(approved_at=approved_at):
                _, problems = pc.judge_queue(self.base, gc, [self.entry(7, c, gc, approved_at=approved_at)])
                self.assertTrue(any("PR #7 is lane C" in p for p in problems), problems)

    def test_approval_of_one_member_does_not_cover_another(self):
        a = self.pr({"docs/reference.md": "changed\n"})
        c = self.pr({"AGENTS.md": "rules, changed\n"})
        ga, gc = self.group(a, c)
        _, problems = pc.judge_queue(self.base, gc, [self.entry(1, a, ga, approved_at=a), self.entry(2, c, gc)])
        self.assertEqual(problems, ["PR #2 is lane C in this group, without @jdueadev's approval of its head"])

    def test_a_path_moved_into_lane_c_earlier_in_the_group_binds_a_later_member(self):
        lanes = (self.tmp / "ci/lanes.toml").read_text(encoding="utf-8")
        moved = lanes.replace("C = [\n", 'C = [\n  "docs/secret.md",\n', 1)
        self.assertNotEqual(moved, lanes)
        first = self.pr({"ci/lanes.toml": moved})
        second = self.pr({"docs/secret.md": "now in lane C\n"})
        g1, g2 = self.group(first, second)
        rows, problems = pc.judge_queue(self.base, g2, [self.entry(1, first, g1, approved_at=first),
                                                         self.entry(2, second, g2)])
        self.assertEqual([r["lane"] for r in rows], ["C", "C"])
        self.assertTrue(any("PR #2 is lane C" in p for p in problems), problems)

    def test_a_ratchet_raises_a_lane_b_member_to_c(self):
        b = self.pr({"claims.toml": CLAIMS.replace("abc1234", "def5678")})
        (gb,) = self.group(b)
        rows, problems = pc.judge_queue(self.base, gb, [self.entry(4, b, gb)])
        self.assertEqual(rows[0]["lane"], "C")
        self.assertTrue(rows[0]["escalations"])
        self.assertTrue(any("PR #4 is lane C" in p for p in problems), problems)

    def test_a_fork_needs_approval_whatever_its_lane(self):
        a = self.pr({"docs/reference.md": "changed\n"})
        (ga,) = self.group(a)
        _, problems = pc.judge_queue(self.base, ga, [self.entry(5, a, ga, fork=True)])
        self.assertTrue(any("PR #5 is from a fork" in p for p in problems), problems)
        _, problems = pc.judge_queue(self.base, ga, [self.entry(5, a, ga, approved_at=a, fork=True)])
        self.assertEqual(problems, [])
        for flag in (None, "false", 0):
            with self.subTest(flag=flag):
                entry = self.entry(5, a, ga)
                entry["fork"] = flag
                _, problems = pc.judge_queue(self.base, ga, [entry])
                self.assertTrue(any("PR #5 is from a fork" in p for p in problems), problems)

    def test_each_commit_must_be_its_own_entrys_group_commit(self):
        a = self.pr({"docs/reference.md": "changed\n"})
        c = self.pr({"AGENTS.md": "rules, changed\n"})
        ga, gc = self.group(c, a)
        _, problems = pc.judge_queue(self.base, gc, [self.entry(1, a, gc, approved_at=a), self.entry(2, c, ga)])
        self.assertTrue(any("PR #1's group commit is" in p for p in problems), problems)
        _, problems = pc.judge_queue(self.base, ga, [self.entry(1, c, None, approved_at=c)])
        self.assertTrue(any("PR #1's group commit is" in p for p in problems), problems)

    def test_what_lands_must_be_the_approved_head_merged(self):
        c = self.pr({"AGENTS.md": "rules, changed\n"})
        extra = self.pr({"AGENTS.md": "rules, changed\n", "docs/reference.md": "unreviewed\n"})
        smuggled = self.land(self.base, c, tree=self.git("rev-parse", f"{extra}^{{tree}}").strip())
        _, problems = pc.judge_queue(self.base, smuggled, [self.entry(1, c, smuggled, approved_at=c)])
        self.assertTrue(any("is not its head merged onto" in p for p in problems), problems)
        (gc,) = self.group(c)
        for head in ("0" * 40, None):
            with self.subTest(head=head):
                _, problems = pc.judge_queue(self.base, gc, [self.entry(1, head, gc, approved_at=head)])
                self.assertTrue(any("is not its head merged onto" in p for p in problems), problems)

    def test_the_group_must_be_one_linear_commit_per_entry_on_the_base(self):
        a = self.pr({"docs/reference.md": "changed\n"})
        (ga,) = self.group(a)
        _, problems = pc.judge_queue(self.base, ga, [self.entry(1, a, ga), self.entry(2, a, ga)])
        self.assertTrue(any("1 commits for 2 entries" in p for p in problems), problems)
        for entries in ([], {"number": 1}, ["not an entry"]):
            with self.subTest(entries=entries):
                _, problems = pc.judge_queue(self.base, ga, entries)
                self.assertTrue(problems)
        side = self.pr({"docs/other.md": "side\n"})
        merged = self.git("commit-tree", self.git("rev-parse", f"{side}^{{tree}}").strip(),
                          "-p", self.base, "-p", side, "-m", "merge").strip()
        _, problems = pc.judge_queue(self.base, merged, [self.entry(1, side, merged)])
        self.assertTrue(any("is not a single-parent commit" in p for p in problems), problems)
        _, problems = pc.judge_queue(side, ga, [self.entry(1, a, ga)])
        self.assertTrue(any("is not an ancestor of" in p for p in problems), problems)

    def test_a_parent_without_a_lane_map_is_refused(self):
        self.git("checkout", "-q", "-b", "nolanes", self.base)
        self.git("rm", "-q", "ci/lanes.toml")
        nolanes = self.commit("no lane map")
        self.git("checkout", "-q", "main")
        a = self.pr({"docs/reference.md": "changed\n"})
        g1 = self.land(self.base, nolanes)
        g2 = self.land(g1, a)
        _, problems = pc.judge_queue(self.base, g2, [self.entry(1, nolanes, g1, approved_at=nolanes),
                                                      self.entry(2, a, g2)])
        self.assertTrue(any("has no ci/lanes.toml" in p for p in problems), problems)

    def test_the_command_fails_only_when_enforced(self):
        c = self.pr({"AGENTS.md": "rules, changed\n"})
        (gc,) = self.group(c)
        entries = self.tmp / "entries.json"
        entries.write_text(json.dumps([self.entry(3, c, gc)]), encoding="utf-8")
        for flags, code in ((["--enforce"], 1), ([], 0)):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(pc.main(["queue", "--base", self.base, "--head", gc, "--entries", str(entries), *flags]),
                                 code)
            self.assertTrue(json.loads(out.getvalue())["problems"])


if __name__ == "__main__":
    unittest.main()
