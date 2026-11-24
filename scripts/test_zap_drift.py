#!/usr/bin/env python3
"""Tests for zap_drift.py: which unported rules are listed, and which count as drift.

Run: python3 scripts/test_zap_drift.py
"""

import contextlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True  # no scripts/__pycache__
import zap_drift


def java(addon, cls):
    return zap_drift.ADDON_JAVA[addon].format(cls)


# Every add-on present, with nothing in it to report.
ALL_ADDONS = [java(addon, "Helper") for addon in zap_drift.RULE_ADDONS]


class UnportedRules(unittest.TestCase):
    def test_lists_each_rule_with_its_addon_and_status(self):
        tree = ALL_ADDONS + [java("pscanrules", "AScanRule"), java("ascanrulesBeta", "CorsScanRule"), java("pscanrulesAlpha", "BScanRule")]
        unported, missing = zap_drift.unported_rules(tree, {}, set())
        self.assertEqual(missing, [])
        self.assertEqual(
            unported,
            [
                {"addon": "pscanrules", "class": "AScanRule", "status": "release", "informational": False},
                {"addon": "ascanrulesBeta", "class": "CorsScanRule", "status": "beta", "informational": True},
                {"addon": "pscanrulesAlpha", "class": "BScanRule", "status": "alpha", "informational": True},
            ],
        )

    def test_ported_skipped_and_helper_classes_are_left_out(self):
        tree = ALL_ADDONS + [
            java("ascanrulesBeta", "PortedScanRule"),
            java("ascanrulesBeta", "SkippedScanRule"),
            java("ascanrulesBeta", "CommonActiveScanRuleInfo"),
            java("ascanrulesBeta", "sub/NestedScanRule"),
            java("client", "ClientPassiveAbstractScanRule"),
            java("client", "ClientPassiveScanRule"),
        ]
        self.assertEqual(zap_drift.unported_rules(tree, {("ascanrulesBeta", "PortedScanRule"): []}, {"SkippedScanRule"}), ([], []))

    def test_a_port_only_covers_its_own_addon(self):
        tree = ALL_ADDONS + [java("ascanrules", "SameScanRule"), java("pscanrules", "SameScanRule")]
        unported, _ = zap_drift.unported_rules(tree, {("ascanrules", "SameScanRule"): []}, set())
        self.assertEqual([u["addon"] for u in unported], ["pscanrules"])

    def test_rules_without_the_suffix_are_found(self):
        tree = ALL_ADDONS + [java("pscanrulesAlpha", "Base64Disclosure"), java("wappalyzer", "TechPassiveScanner"), java("saml", "SAMLPassiveScanner")]
        unported, _ = zap_drift.unported_rules(tree, {}, set())
        self.assertEqual([u["class"] for u in unported], ["Base64Disclosure", "TechPassiveScanner", "SAMLPassiveScanner"])

    def test_every_rule_addon_has_a_path(self):
        self.assertLessEqual(set(zap_drift.RULE_ADDONS), set(zap_drift.ADDON_JAVA))
        self.assertLessEqual(zap_drift.DRIFT_ADDONS, set(zap_drift.RULE_ADDONS))


class ExitCode(unittest.TestCase):
    """main() against a throwaway upstream repository."""

    def run_main(self, files, *flags, later=(), feed=None):
        """`later` files land in a second upstream commit; `feed` is the feed rule's entry,
        whose "commit" may be "first" or "head"."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            upstream = tmp / "upstream"
            for f in files:
                path = upstream / f
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("class X {}\n")
            git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"]
            subprocess.run(["git", "init", "-q", "-b", "main", str(upstream)], check=True)
            subprocess.run([*git, "-C", str(upstream), "add", "."], check=True)
            subprocess.run([*git, "-C", str(upstream), "commit", "-qm", "x"], check=True)
            rev = lambda: subprocess.run(["git", "-C", str(upstream), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
            commit = rev()
            for f in later:
                path = upstream / f
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("changed\n")
            if later:
                subprocess.run([*git, "-C", str(upstream), "add", "."], check=True)
                subprocess.run([*git, "-C", str(upstream), "commit", "-qm", "later"], check=True)
            subprocess.run(["git", "clone", "-q", str(upstream), str(tmp / "clone")], check=True)
            sync = tmp / "zap-sync.json"
            config = {"repository": str(upstream), "commit": commit}
            if feed is not None:
                feed = dict(feed)
                if "commit" in feed:
                    feed["commit"] = commit if feed["commit"] == "first" else rev()
                config["feed_rules"] = {"ServerSideVersionScanRule": feed}
            sync.write_text(json.dumps(config))
            out = io.StringIO()
            # A ROOT without crates/: nothing is ported.
            with mock.patch.object(zap_drift, "SYNC", sync), mock.patch.object(zap_drift, "ROOT", tmp), mock.patch.object(sys, "argv", ["zap_drift", "--repo", str(tmp / "clone"), *flags]):
                with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as caught:
                    zap_drift.main()
            return caught.exception.code, out.getvalue()

    def test_beta_and_alpha_alone_are_not_drift(self):
        code, out = self.run_main(ALL_ADDONS + [java("ascanrulesBeta", "CorsScanRule"), java("ascanrulesAlpha", "LdapInjectionScanRule")])
        self.assertEqual(code, 0)
        self.assertIn("informational", out)
        self.assertIn("ascanrulesBeta/CorsScanRule (beta)", out)
        self.assertIn("ascanrulesAlpha/LdapInjectionScanRule (alpha)", out)
        self.assertIn("No drift.", out)

    def test_unported_release_rule_is_drift(self):
        code, out = self.run_main(ALL_ADDONS + [java("ascanrules", "NewScanRule")])
        self.assertEqual(code, 10)
        self.assertIn("ascanrules/NewScanRule (release)", out)
        self.assertNotIn("No drift.", out)

    def test_release_status_outside_the_drift_addons_is_not_drift(self):
        code, out = self.run_main(ALL_ADDONS + [java("domxss", "DomXssScanRule")])
        self.assertEqual(code, 0)
        self.assertIn("domxss/DomXssScanRule (release)", out)

    def test_removed_alpha_addon_is_reported_without_failing(self):
        tree = [f for f in ALL_ADDONS if "/ascanrulesAlpha/" not in f]
        code, out = self.run_main(tree)
        self.assertEqual(code, 0)
        self.assertIn("Add-on not found upstream: ascanrulesAlpha (informational)", out)

    def test_removed_release_addon_is_drift(self):
        code, out = self.run_main([f for f in ALL_ADDONS if "/pscanrules/" not in f])
        self.assertEqual(code, 10)
        self.assertIn("Add-on not found upstream: pscanrules", out)

    def test_json_marks_informational_entries(self):
        code, out = self.run_main(ALL_ADDONS + [java("pscanrulesBeta", "CacheableScanRule")], "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["unported"], [{"addon": "pscanrulesBeta", "class": "CacheableScanRule", "status": "beta", "informational": True}])

    def test_a_feed_rule_can_pin_its_own_commit(self):
        data = "addOns/pscanrules/data/nginx-known-vulnerabilities.json"
        feed = {"addon": "pscanrules", "generator": "scripts/version_feed.py", "data": [data], "ours": "feed/passive/nginx/"}
        files = ALL_ADDONS + [java("pscanrules", "ServerSideVersionScanRule")]
        # Data changed after the ports' pin: the feed is to be regenerated.
        code, out = self.run_main(files, "--json", later=[data], feed=feed)
        self.assertEqual(code, 10)
        self.assertEqual([c["commits"][0].split(" ", 1)[1] for c in json.loads(out)["feed_changed"]], ["later"])
        # The feed pinned at that change is in sync, though the ports' pin is older.
        code, out = self.run_main(files, "--json", later=[data], feed={**feed, "commit": "head"})
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["feed_changed"], [])


if __name__ == "__main__":
    unittest.main()
