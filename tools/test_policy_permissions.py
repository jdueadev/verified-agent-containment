#!/usr/bin/env python3
"""Tests for the shared `permissions` rules in tools/policy_check.py (#173).

A tracked .claude/settings.json may hold `permissions`, and only in a form that
restricts: `deny`, `ask` and `disableBypassPermissionsMode: "disable"`. `allow` and
every scalar that could override a user's own stricter value are refused.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import policy_check as pc

GOOD = {"deny": ["Edit(/results/**)", "Bash(cargo fmt *)"], "ask": ["Bash(git push *)"],
        "disableBypassPermissionsMode": "disable"}


def errors(permissions=None, text=None):
    return pc.settings_errors(text if text is not None else json.dumps({"permissions": permissions}))


class AcceptedTests(unittest.TestCase):
    def test_restricting_file_passes(self):
        self.assertEqual(errors(GOOD), [])

    def test_each_restricting_key_alone_passes(self):
        for key, value in GOOD.items():
            self.assertEqual(errors({key: value}), [], key)

    def test_through_claude_path_errors(self):
        tree = {pc.CLAUDE_SETTINGS: ("100644", "0" * 40)}
        self.assertEqual(pc.claude_path_errors(tree, lambda path: json.dumps({"permissions": GOOD})), [])


class RejectedKeyTests(unittest.TestCase):
    def assert_one(self, found, phrase):
        self.assertEqual(len(found), 1, found)
        self.assertIn(phrase, found[0])

    def test_loosening_and_overriding_keys_fail(self):
        for key, value in (("allow", ["Bash(python3 tools/policy_check.py invariants)"]),
                           ("defaultMode", "bypassPermissions"), ("defaultMode", "plan"),
                           ("additionalDirectories", ["/"]), ("blockWritesOutsideWorkingDirectories", False),
                           ("blockReadsOutsideWorkingDirectories", True), ("denyInsteadOfPrompting", True),
                           ("Allow", ["Bash(*)"]), ("Deny", ["Bash(x)"]), ("unknown", 1)):
            self.assert_one(errors({"deny": ["Bash(x)"], key: value}), f"key {key!r} is not allowed")

    def test_disable_bypass_must_be_exactly_disable(self):
        for value in (True, "Disable", "disabled", "", None, 1):
            self.assert_one(errors({"disableBypassPermissionsMode": value}), "must be exactly \"disable\"")

    def test_permissions_must_be_a_non_empty_object(self):
        self.assert_one(errors({}), "'permissions' is empty")
        for value in ([], ["deny"], "deny", None, 1, True):
            self.assert_one(errors(value), "'permissions' is not an object")

    def test_other_settings_keys_stay_refused(self):
        found = errors(text=json.dumps({"permissions": GOOD, "hooks": {}, "env": {"X": "1"}}))
        self.assertEqual(len(found), 2, found)
        self.assertTrue(all("is not allowed yet" in e for e in found), found)


class RuleListTests(unittest.TestCase):
    def found(self, rules, name="deny"):
        return errors({name: rules})

    def assert_phrase(self, found, phrase):
        self.assertTrue(found and all(phrase in e for e in found), found)

    def test_rule_list_must_be_a_list(self):
        for value in ("Bash(x)", {"Bash(x)": True}, None, 3, True):
            for name in ("deny", "ask"):
                self.assert_phrase(self.found(value, name), "is not a list")

    def test_rules_must_be_strings(self):
        for item in (True, False, 1, 1.5, None, ["Bash(x)"], {"x": 1}):
            self.assert_phrase(self.found([item]), "is not a string")

    def test_rules_are_unique(self):
        self.assert_phrase(self.found(["Bash(x)", "Bash(y)", "Bash(x)"]), "repeats 'Bash(x)'")

    def test_rule_length(self):
        self.assertEqual(self.found(["B" * 200]), [])
        self.assert_phrase(self.found(["B" * 201]), "longer than 200")
        self.assert_phrase(self.found([""]), "is empty")

    def test_rule_count(self):
        self.assertEqual(self.found([f"Bash(x{i})" for i in range(64)]), [])
        self.assert_phrase(self.found([f"Bash(x{i})" for i in range(65)]), "more than 64")

    def test_rules_are_printable_ascii(self):
        for rule in ("Bash(x\x00)", "Bash(x\ny)", "Bash(x\ry)", "Bash(x\ty)", "Bash(x‮y)",
                     "Bash(x‍y)", "Bash(é)", "Edit(/rеsults/**)"):
            self.assert_phrase(self.found([rule]), "is not printable ASCII")


class JsonTests(unittest.TestCase):
    def test_non_json_constants_fail(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            found = errors(text='{"permissions": {"deny": ["Bash(x)"]}, "n": ' + constant + "}")
            self.assertEqual(len(found), 1, constant)
            self.assertIn(f"{constant} is not JSON", found[0])

    def test_duplicate_keys_fail_inside_permissions(self):
        found = errors(text='{"permissions": {"deny": ["Bash(x)"], "deny": []}}')
        self.assertEqual(len(found), 1)
        self.assertIn("duplicate key 'deny'", found[0])

    def test_escaped_key_is_the_same_key(self):
        found = errors(text='{"permissions": {"\\u0061llow": ["Bash(*)"]}}')
        self.assertEqual(len(found), 1)
        self.assertIn("key 'allow' is not allowed", found[0])


if __name__ == "__main__":
    unittest.main()
