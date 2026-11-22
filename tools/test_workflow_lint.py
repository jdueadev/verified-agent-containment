#!/usr/bin/env python3
"""Unit tests for tools/workflow_lint.py. Each rule has a case that makes it fire."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import workflow_lint as wl

ROOT = Path(__file__).resolve().parent.parent
ALLOWED = {"evidence"}

# A job that reads a secret the way lab.yaml's record job does.
GOOD = """\
name: demo
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  record:
    environment: evidence
    runs-on: ubuntu-24.04
    steps:
      - name: App token
        id: app
        uses: actions/create-github-app-token@abc
        with:
          private-key: ${{ secrets.KEY }}
      - uses: actions/checkout@abc
        with:
          ref: ${{ github.sha }}
          token: ${{ steps.app.outputs.token }}
      - name: Use it
        env:
          TITLE: ${{ github.event.pull_request.title }}
        run: |
          echo "$TITLE"
          echo ${{ github.sha }} ${{ github.event_name }}
"""


def lint(text):
    return wl.lint("w.yml", text, ALLOWED)


class Repository(unittest.TestCase):
    def test_the_repository_workflows_pass(self):
        allowed = wl.load_allowed((ROOT / wl.ALLOW_FILE).read_text(encoding="utf-8"))
        files = wl.workflow_files(ROOT)
        self.assertTrue(files)
        self.assertEqual([e for n, t in files.items() for e in wl.lint(n, t, allowed)], [])

    def test_the_allowlist_names_exactly_evidence_and_gate(self):
        # Each name is an environment limited to main (#137). Adding one needs the maintainer.
        self.assertEqual(wl.load_allowed((ROOT / wl.ALLOW_FILE).read_text(encoding="utf-8")), {"evidence", "gate"})


class Secrets(unittest.TestCase):
    def test_good_workflow_passes(self):
        self.assertEqual(lint(GOOD), [])

    def test_environment_given_as_a_name_mapping_passes(self):
        text = GOOD.replace("    environment: evidence\n", "    environment:\n      name: evidence\n")
        self.assertEqual(lint(text), [])

    def test_quoted_environment_passes(self):
        self.assertEqual(lint(GOOD.replace("environment: evidence", "environment: 'evidence'")), [])

    def test_secret_without_environment_fails(self):
        errors = lint(GOOD.replace("    environment: evidence\n", ""))
        self.assertTrue(any("reads a secret with no environment" in e for e in errors), errors)

    def test_secret_with_an_environment_not_on_the_allowlist_fails(self):
        errors = lint(GOOD.replace("environment: evidence", "environment: staging"))
        self.assertTrue(any("environment 'staging'" in e for e in errors), errors)

    def test_environment_from_an_expression_fails(self):
        for env in ("${{ github.ref_name }}", "evidence-${{ inputs.x }}"):
            with self.subTest(env=env):
                errors = lint(GOOD.replace("environment: evidence", f"environment: {env}"))
                self.assertTrue(any("must be a plain name" in e for e in errors), errors)

    def test_every_form_of_secret_access_counts(self):
        for form in ("${{ secrets['KEY'] }}", "${{ toJSON(secrets) }}", "${{ secrets }}",
                     "${{ format('{0}', secrets.KEY) }}", "x-${{ secrets.KEY }}"):
            with self.subTest(form=form):
                errors = lint(GOOD.replace("    environment: evidence\n", "")
                              .replace("${{ secrets.KEY }}", form))
                self.assertTrue(any("reads a secret" in e for e in errors), errors)

    def test_secret_in_a_run_script_counts(self):
        text = GOOD.replace("    environment: evidence\n", "").replace(
            "          echo \"$TITLE\"\n", "          curl -H \"x: ${{ secrets.KEY }}\" example.invalid\n")
        self.assertTrue(any("reads a secret" in e for e in lint(text)))

    def test_secret_at_workflow_level_fails(self):
        text = GOOD.replace("permissions:\n", "env:\n  KEY: ${{ secrets.KEY }}\npermissions:\n")
        self.assertTrue(any("a secret outside a job" in e for e in lint(text)))

    def test_secrets_passed_to_a_reusable_workflow_fail(self):
        for passing in ("    secrets: inherit\n", "    secrets:\n      key: ${{ secrets.KEY }}\n"):
            with self.subTest(passing=passing):
                text = ("on: push\njobs:\n  call:\n    uses: ./.github/workflows/other.yml\n" + passing)
                self.assertTrue(any("reusable workflow" in e for e in lint(text)), lint(text))


class JobsWithKeys(unittest.TestCase):
    def test_checkout_of_pull_request_code_fails(self):
        for ref in ("${{ github.event.pull_request.head.sha }}", "${{ github.head_ref }}",
                    "refs/pull/1/merge", "${{ github.event.workflow_run.head_sha }}", "'${{ github.sha }}x'"):
            with self.subTest(ref=ref):
                errors = lint(GOOD.replace("ref: ${{ github.sha }}", f"ref: {ref}"))
                self.assertTrue(any("checks out" in e for e in errors), errors)

    def test_quoted_github_sha_passes(self):
        self.assertEqual(lint(GOOD.replace("ref: ${{ github.sha }}", "ref: '${{ github.sha }}'")), [])

    def test_refused_inputs_fail(self):
        for key in wl.REFUSED_WITH:
            with self.subTest(key=key):
                errors = lint(GOOD.replace("          token: ", f"          {key}: x\n          token: "))
                self.assertTrue(any(f"sets '{key}'" in e for e in errors), errors)

    def test_environment_alone_brings_the_rules(self):
        text = GOOD.replace("${{ secrets.KEY }}", "plain").replace(
            "ref: ${{ github.sha }}", "ref: ${{ github.event.pull_request.head.sha }}")
        self.assertTrue(any("checks out" in e for e in lint(text)))

    def test_jobs_without_keys_may_check_out_pull_request_code(self):
        text = GOOD.replace("    environment: evidence\n", "").replace("${{ secrets.KEY }}", "plain").replace(
            "ref: ${{ github.sha }}", "ref: ${{ github.event.pull_request.head.sha }}")
        self.assertEqual(lint(text), [])


class Scripts(unittest.TestCase):
    def test_event_text_in_a_script_fails(self):
        for expr in ("${{ github.event.pull_request.title }}", "${{ github.head_ref }}",
                     "${{ toJSON(github) }}", "${{ github['event'] }}", "${{ github.event_path && github.event.x }}"):
            with self.subTest(expr=expr):
                errors = lint(GOOD.replace("echo \"$TITLE\"", f"echo {expr}"))
                self.assertTrue(any("a script expands" in e for e in errors), errors)

    def test_event_text_in_a_shell_comment_still_fails(self):
        # GitHub expands expressions before the shell sees the script.
        errors = lint(GOOD.replace("echo \"$TITLE\"", "# ${{ github.event.issue.title }}"))
        self.assertTrue(any("a script expands" in e for e in errors), errors)

    def test_event_text_in_a_one_line_script_fails(self):
        text = GOOD.replace("        run: |\n          echo \"$TITLE\"\n",
                            "        run: echo ${{ github.event.pull_request.title }}\n")
        self.assertTrue(any("a script expands" in e for e in lint(text)))

    def test_safe_github_fields_pass(self):
        text = GOOD.replace("echo \"$TITLE\"", "echo ${{ github.run_id }} ${{ github.repository }} ${{ github.event_name }}")
        self.assertEqual(lint(text), [])

    def test_unclosed_expression_fails(self):
        errors = lint(GOOD.replace("echo \"$TITLE\"", "echo ${{ github.sha"))
        self.assertTrue(any("never closed" in e for e in errors), errors)

    def test_expression_across_lines_of_a_folded_scalar_is_read(self):
        text = GOOD.replace("permissions:\n", "concurrency:\n  group: >-\n    a-${{\n    github.ref }}\npermissions:\n")
        self.assertEqual(lint(text), [])


class Unreadable(unittest.TestCase):
    def test_yaml_this_reader_does_not_follow_fails(self):
        cases = {
            "anchor": GOOD.replace("permissions:\n  contents: read\n", "permissions: &p\n  contents: read\n"),
            "alias": GOOD.replace("    runs-on: ubuntu-24.04\n", "    runs-on: *os\n"),
            "merge key": GOOD.replace("    runs-on: ubuntu-24.04\n", "    <<: {a: b}\n    runs-on: x\n"),
            "flow mapping": GOOD.replace("permissions:\n  contents: read\n", "permissions: {contents: read}\n"),
            "flow mapping in a sequence": GOOD.replace("    steps:\n", "    steps:\n      - {run: x}\n"),
            "alias in a flow sequence": GOOD.replace("branches: [main]", "branches: [*b]"),
            "tag": GOOD.replace("    runs-on: ubuntu-24.04\n", "    runs-on: !!str x\n"),
            "tab": GOOD.replace("    runs-on: ubuntu-24.04\n", "\truns-on: x\n"),
            "document marker": "---\n" + GOOD,
            "compact sequence": GOOD.replace("    steps:\n      - name: App token\n", "    steps:\n    - name: App token\n"),
            "complex key": GOOD.replace("permissions:\n", "? x\n: y\npermissions:\n"),
            "unreadable line": GOOD.replace("permissions:\n  contents: read\n", "permissions:\n  contents: read\nnot a key\n"),
        }
        for label, text in cases.items():
            with self.subTest(label=label):
                self.assertNotEqual(lint(text), [], label)

    def test_allowlist_must_be_a_list_of_plain_names(self):
        for text in ("", "secret_environments = 'evidence'\n", "secret_environments = ['a b']\n",
                     "secret_environments = [1]\n", "secret_environments = [\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                wl.load_allowed(text)


class ReviewBypasses(unittest.TestCase):
    """Texts that passed the first version of the lint (#137, stage 1 review). Each must fail."""

    def assertFails(self, text, needle):
        errors = lint(text)
        self.assertTrue(any(needle in e for e in errors), errors)

    def test_context_names_ignore_case(self):
        no_env = GOOD.replace("    environment: evidence\n", "")
        for form in ("${{ Secrets.KEY }}", "${{ SECRETS['KEY'] }}", "${{ toJSON(SeCrEtS) }}"):
            with self.subTest(form=form):
                self.assertFails(no_env.replace("${{ secrets.KEY }}", form), "reads a secret")
        for expr in ("${{ GitHub.Event.head_commit.message }}", "${{ github.EVENT.x }}", "${{ github.Head_Ref }}"):
            with self.subTest(expr=expr):
                self.assertFails(GOOD.replace('echo "$TITLE"', f"echo {expr}"), "a script expands")

    def test_input_and_key_names_ignore_case(self):
        self.assertFails(GOOD.replace("ref: ${{ github.sha }}", "Ref: ${{ github.event.pull_request.head.sha }}"),
                         "checks out")
        self.assertFails(GOOD.replace("          token: ", "          REPOSITORY: x\n          token: "),
                         "sets 'repository'")
        self.assertFails(GOOD.replace("    environment: evidence\n", "    Environment: staging\n"),
                         "environment 'staging'")

    def test_explicit_keys_and_values_on_the_next_line_fail(self):
        cases = [
            GOOD.replace("          ref: ${{ github.sha }}\n",
                         "          ? ref\n          : ${{ github.event.pull_request.head.sha }}\n"),
            GOOD.replace("      - name: Use it\n", "      - ? run\n        : echo ${{ github.event.pull_request.title }}\n"
                         "      - name: Use it\n"),
            "on: push\njobs:\n  call:\n    ? secrets\n    : inherit\n    uses: ./.github/workflows/other.yml\n",
            GOOD.replace("          ref: ${{ github.sha }}\n",
                         "          fetch depth: 1\n          ref: ${{ github.event.pull_request.head.sha }}\n"),
            GOOD.replace("    runs-on: ubuntu-24.04\n", "    runs-on:\n      ubuntu-24.04\n"),
        ]
        for text in cases:
            with self.subTest(text=text[-160:]):
                self.assertNotEqual(lint(text), [])

    def test_lone_cr_and_unicode_line_breaks_fail(self):
        for brk in ("\r", "\x85", "\u2028", "\u2029"):
            with self.subTest(brk=repr(brk)):
                text = GOOD.replace("    runs-on: ubuntu-24.04\n", f"    runs-on: ubuntu-24.04{brk}    steps: []\n")
                self.assertFails(text, "line break")

    def test_crlf_and_a_bom_are_read(self):
        self.assertEqual(lint("\ufeff" + GOOD.replace("\n", "\r\n")), [])

    def test_flow_sequences_holding_mappings_fail(self):
        for steps in ("    steps: [ run: echo ${{ github.event.head_commit.message }} ]\n",
                      "    steps: [\n      run: echo x ]\n",
                      "    steps: [ [a], b ]\n",
                      "    steps: [ ? a ]\n",
                      "    steps: [ *a ]\n"):
            with self.subTest(steps=steps):
                text = "on: push\njobs:\n  a:\n    runs-on: x\n" + steps
                self.assertFails(text, "flow sequence")

    def test_plain_flow_sequences_pass(self):
        text = GOOD.replace("branches: [main]", "branches: [main, 'release/*', \"x\"]  # note")
        self.assertEqual(lint(text), [])

    def test_env_and_other_laundering_contexts_fail_in_scripts(self):
        for expr in ("${{ env.T }}", "${{ steps.app.outputs.token }}", "${{ needs.a.outputs.x }}",
                     "${{ inputs.x }}", "${{ matrix.x }}", "${{ github.ref_name }}", "${{ github.ref }}",
                     "${{ vars.X }}", "${{ fromJSON(github.event.x) }}"):
            with self.subTest(expr=expr):
                self.assertFails(GOOD.replace('echo "$TITLE"', f"echo {expr}"), "a script expands")

    def test_script_inputs_are_scripts(self):
        text = GOOD.replace("          token: ${{ steps.app.outputs.token }}\n",
                            "          token: ${{ steps.app.outputs.token }}\n          script: ${{ github.event.x }}\n")
        self.assertFails(text, "a script expands")

    def test_composite_actions_are_linted(self):
        action = "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo ${{ github.event.x }}\n"
        self.assertFails(action, "a script expands")

    def test_quoted_close_does_not_end_an_expression(self):
        no_env = GOOD.replace("    environment: evidence\n", "")
        self.assertFails(no_env.replace("${{ secrets.KEY }}", "${{ format('}}', secrets.KEY) }}"), "reads a secret")

    def test_block_scalar_indentation_indicators_fail(self):
        self.assertNotEqual(lint(GOOD.replace("        run: |\n", "        run: |2\n")), [])


class HonestScripts(unittest.TestCase):
    """Shapes the first version refused that are plain YAML and safe."""

    def test_braces_inside_a_plain_value_pass(self):
        for run in ("find . -exec rm {} \\;", "echo ${HOME}"):
            with self.subTest(run=run):
                text = GOOD.replace("        run: |\n          echo \"$TITLE\"\n", f"        run: {run}\n")
                self.assertEqual(lint(text.replace("          echo ${{ github.sha }} ${{ github.event_name }}\n", "")), [])

    def test_reusable_workflow_secret_declarations_pass(self):
        text = "on:\n  workflow_call:\n    secrets:\n      key:\n        required: true\njobs:\n  a:\n    runs-on: x\n"
        self.assertEqual(lint(text), [])


class SecondReviewBypasses(unittest.TestCase):
    """Texts that passed the second version (#137, stage 1 re-review). Each must fail."""

    def assertFails(self, text, needle):
        errors = lint(text)
        self.assertTrue(any(needle in e for e in errors), errors)

    def test_escapes_in_double_quoted_strings_fail(self):
        no_env = GOOD.replace("    environment: evidence\n", "")
        for form in ('"$\\x7B{ secrets.KEY }}"', '"${{ \\x73ecrets.KEY }}"', '"${{ \\u0073ecrets.KEY }}"'):
            with self.subTest(form=form):
                self.assertFails(no_env.replace("${{ secrets.KEY }}", form), "backslash in a double-quoted string")
        self.assertFails(GOOD.replace("        run: |\n          echo \"$TITLE\"\n",
                                      '        run: "echo $\\\n          {{ github.event.x }}"\n'),
                         "backslash in a double-quoted string")
        self.assertFails(GOOD.replace("          ref: ${{ github.sha }}\n",
                                      '          "r\\x65f": ${{ github.event.pull_request.head.sha }}\n'),
                         "backslash in a key")
        self.assertFails(GOOD.replace("branches: [main]", 'branches: ["m\\x61in"]'),
                         "backslash in a double-quoted string")

    def test_backslashes_in_block_scripts_pass(self):
        text = GOOD.replace('echo "$TITLE"', 'printf "%s\\n" "$TITLE" | sed "s/a\\.b/c/"')
        self.assertEqual(lint(text), [])

    def test_json_style_key_in_a_flow_sequence_fails(self):
        text = 'on: push\njobs:\n  a:\n    runs-on: x\n    steps: [ "run":"echo ${{ github.event.x }}" ]\n'
        self.assertFails(text, "flow sequence")

    def test_shell_and_command_inputs_are_scripts(self):
        for step in ('        shell: bash -c "echo ${{ github.event.x }}; bash {0}"\n',
                     "        with:\n          args: -c echo ${{ github.event.x }}\n",
                     "        with:\n          entrypoint: ${{ github.event.x }}\n",
                     "        with:\n          command: ${{ github.event.x }}\n"):
            with self.subTest(step=step):
                text = GOOD.replace("      - name: Use it\n", "      - uses: docker://alpine\n" + step +
                                    "      - name: Use it\n")
                self.assertFails(text, "a script expands")


class ReadThroughGit(unittest.TestCase):
    def test_ref_mode_reads_the_commit_not_the_working_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = lambda *a: subprocess.run(["git", "-C", tmp, *a], check=True, capture_output=True)
            run("init", "-q")
            run("config", "user.email", "t@example.invalid")
            run("config", "user.name", "t")
            (root / wl.WORKFLOWS).mkdir(parents=True)
            (root / wl.WORKFLOWS / "a.yml").write_text(GOOD)
            (root / wl.WORKFLOWS / "notes.txt").write_text("ignored")
            (root / wl.WORKFLOWS / "sub").mkdir()
            (root / wl.WORKFLOWS / "sub" / "x.yml").write_text("ignored: GitHub runs only the top level\n")
            (root / ".github/actions/do").mkdir(parents=True)
            (root / ".github/actions/do/action.yml").write_text("runs:\n  using: composite\n")
            # `uses: ./ci/act` runs an action.yml anywhere in the repository.
            (root / "ci/act").mkdir(parents=True)
            (root / "ci/act/action.yaml").write_text("runs:\n  using: composite\n")
            run("add", "-A")
            run("commit", "-q", "-m", "one")
            (root / wl.WORKFLOWS / "a.yml").write_text("changed in the tree only\n")
            files = wl.workflow_files(root, "HEAD")
            self.assertEqual(list(files), [".github/actions/do/action.yml", f"{wl.WORKFLOWS}/a.yml",
                                           "ci/act/action.yaml"])
            self.assertEqual(wl.workflow_files(root), files | {f"{wl.WORKFLOWS}/a.yml": "changed in the tree only\n"})
            self.assertEqual(files[f"{wl.WORKFLOWS}/a.yml"], GOOD)
            self.assertEqual(wl.lint("a.yml", files[f"{wl.WORKFLOWS}/a.yml"], ALLOWED), [])
            with self.assertRaises(subprocess.CalledProcessError):
                wl.workflow_files(root, "no-such-ref")


if __name__ == "__main__":
    unittest.main()
