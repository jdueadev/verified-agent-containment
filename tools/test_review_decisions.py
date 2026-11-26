"""Runs the script in .github/workflows/review-decisions.yml against a stand-in for the GitHub API."""
import contextlib
import io
import textwrap
import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "review-decisions.yml"
HEAD = "0123456789abcdef0123456789abcdef01234567"
OWNER = "jdueadev"


def workflow_script():
    """Everything below the workflow's one "run: |", as the runner hands it to python3."""
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip() == "run: |"]
    assert len(starts) == 1, starts
    indent = len(lines[starts[0]]) - len(lines[starts[0]].lstrip())
    body = []
    for line in lines[starts[0] + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) <= indent:
            break
        body.append(line)
    return textwrap.dedent("\n".join(body))


SCRIPT = compile(workflow_script(), str(WORKFLOW), "exec")


class Api:
    """The two endpoints the script reads: the changed files, a page at a time, and the pull request."""

    def __init__(self, files, head=HEAD, changed=None):
        self.files, self.head = files, head
        self.changed = len(files) if changed is None else changed
        self.calls = 0

    def __call__(self, path):
        self.calls += 1
        if "/files?" in path:
            page = int(path.rsplit("page=", 1)[1])
            return self.files[(page - 1) * 100:page * 100]
        return {"head": {"sha": self.head}, "changed_files": self.changed}


def changed(*names, renamed_from=None):
    return [{"filename": n, **({"previous_filename": renamed_from} if renamed_from else {})} for n in names]


class ReviewDecisions(unittest.TestCase):
    def run_check(self, author, api, **env):
        namespace = {"__name__": "review_decisions"}
        exec(SCRIPT, namespace)
        env = {"REPO": "vac-dev-team/verified-agent-containment", "PR": "271", "HEAD": HEAD,
               "OWNER": OWNER, "AUTHOR": author, **env}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = namespace["main"](env, api)
        return status, out.getvalue()

    def assertRefused(self, result, path):
        status, out = result
        self.assertEqual(status, 1, out)
        self.assertIn(f'path: "{path}"', out)
        self.assertIn("::error::review-decisions: only the owner's pull requests", out)

    def test_owner_changes_a_decision_file_passes(self):
        api = Api(changed("ci/verifier-removals.toml", "evals/agentdojo/expected-differences.toml"))
        self.assertEqual(self.run_check(OWNER, api)[0], 0)
        self.assertEqual(api.calls, 0)

    def test_someone_else_changes_a_decision_file_fails(self):
        self.assertRefused(self.run_check("agent", Api(changed("tools/eval_diff.py", "ci/verifier-removals.toml"))),
                           "ci/verifier-removals.toml")
        self.assertRefused(self.run_check("agent", Api(changed("evals/agentdojo/expected-differences.toml"))),
                           "evals/agentdojo/expected-differences.toml")

    def test_someone_else_changes_neither_passes(self):
        status, out = self.run_check("agent", Api(changed("tools/eval_diff.py", "ci/pins.env", "evals/README.md")))
        self.assertEqual(status, 0, out)
        self.assertIn("No decision file changed (3 files).", out)

    def test_a_file_renamed_onto_or_off_a_decision_file_fails(self):
        self.assertRefused(self.run_check("agent", Api(changed("ci/verifier-removals.toml", renamed_from="ci/notes.toml"))),
                           "ci/verifier-removals.toml")
        self.assertRefused(self.run_check("agent", Api(changed("ci/old.toml", renamed_from="ci/verifier-removals.toml"))),
                           "ci/verifier-removals.toml")

    def test_a_directory_above_a_decision_file_or_another_case_fails(self):
        self.assertRefused(self.run_check("agent", Api(changed("evals/agentdojo"))), "evals/agentdojo")
        self.assertRefused(self.run_check("agent", Api(changed("CI/Verifier-Removals.toml"))), "CI/Verifier-Removals.toml")

    def test_every_page_of_changed_files_is_read(self):
        files = changed(*(f"src/{i}.rs" for i in range(150)), "ci/verifier-removals.toml")
        self.assertRefused(self.run_check("agent", Api(files)), "ci/verifier-removals.toml")

    def test_a_list_that_is_not_the_whole_change_at_head_fails(self):
        for api in (Api(changed("README.md"), head="f" * 40), Api(changed("README.md"), changed=3001)):
            status, out = self.run_check("agent", api)
            self.assertEqual(status, 1, out)
            self.assertIn("::error::review-decisions: listed 1 files", out)

    def test_missing_event_values_fail(self):
        for env in ({"PR": ""}, {"PR": "1; true"}, {"HEAD": "main"}, {"AUTHOR": ""}, {"OWNER": ""}):
            status, out = self.run_check("agent", Api([]), **env)
            self.assertEqual(status, 1, (env, out))
            self.assertIn("::error::", out)


if __name__ == "__main__":
    unittest.main()
