#!/usr/bin/env python3
"""Report upstream changes to the ZAP rules brainproxy has ported.

Every ported rule file starts with a header like
    //! Ported from ZAP CrlfInjectionScanRule (ascanrules, Apache License 2.0).
This script finds those headers, maps each to its Java file in zaproxy/zap-extensions,
and compares the pinned commit (zap-sync.json) with upstream HEAD. It also lists rules
that exist upstream but are not ported yet, each with its add-on and ZAP status, and
changes to the data files we copied.

Usage: scripts/zap_drift.py [--repo PATH_TO_ZAP_EXTENSIONS_CLONE] [--json]
Without --repo it clones zap-extensions (blobless, sparse) into a temp dir.
Exit code 0: no drift; 10: drift found (report printed); other: error.
Unported rules outside pscanrules and ascanrules are informational: they are reported
(also in --json, with "informational": true) but don't count as drift.
"""

import argparse
import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SYNC = ROOT / "zap-sync.json"
HEADER = re.compile(r"Ported from ZAP (.+?) \(([A-Za-z, ]+?), Apache License 2\.0\)")
ADDON_JAVA = {
    "pscanrules": "addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/{}.java",
    "ascanrules": "addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/{}.java",
    "ascanrulesBeta": "addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/{}.java",
    "pscanrulesBeta": "addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/{}.java",
    "ascanrulesAlpha": "addOns/ascanrulesAlpha/src/main/java/org/zaproxy/zap/extension/ascanrulesAlpha/{}.java",
    "pscanrulesAlpha": "addOns/pscanrulesAlpha/src/main/java/org/zaproxy/zap/extension/pscanrulesAlpha/{}.java",
    "domxss": "addOns/domxss/src/main/java/org/zaproxy/zap/extension/domxss/{}.java",
    "sqliplugin": "addOns/sqliplugin/src/main/java/org/zaproxy/zap/extension/sqliplugin/{}.java",
    "soap": "addOns/soap/src/main/java/org/zaproxy/zap/extension/soap/{}.java",
    "imagelocationscanner": "addOns/imagelocationscanner/src/main/java/org/zaproxy/zap/extension/imagelocationscanner/{}.java",
    "httpsInfo": "addOns/httpsInfo/src/main/java/org/zaproxy/zap/extension/httpsinfo/{}.java",
    "client": "addOns/client/src/main/java/org/zaproxy/addon/client/pscan/{}.java",
    "saml": "addOns/saml/src/main/java/org/zaproxy/zap/extension/saml/{}.java",
    "wappalyzer": "addOns/wappalyzer/src/main/java/org/zaproxy/zap/extension/wappalyzer/{}.java",
    "commonlib": "addOns/commonlib/src/main/java/org/zaproxy/addon/commonlib/{}.java",
    "retire": "addOns/retire/src/main/java/org/zaproxy/addon/retire/{}.java",
}
# Add-ons searched for unported rules, with ZAP's status for each (addOnStatus in the
# add-on's gradle.kts; alpha when unset). Left out: add-ons whose "rules" only wrap
# scripts (scripts, websocket) or serve ZAP itself (authhelper, params, pscan, foxhound).
RULE_ADDONS = {
    "pscanrules": "release",
    "ascanrules": "release",
    "pscanrulesBeta": "beta",
    "ascanrulesBeta": "beta",
    "pscanrulesAlpha": "alpha",
    "ascanrulesAlpha": "alpha",
    "domxss": "release",
    "retire": "release",
    "wappalyzer": "release",
    "imagelocationscanner": "beta",
    "soap": "beta",
    "sqliplugin": "beta",
    "client": "alpha",
    "httpsInfo": "alpha",
    "saml": "alpha",
}
# We aim to port everything in these; an unported rule anywhere else is informational,
# or the drift issue could never close.
DRIFT_ADDONS = {"pscanrules", "ascanrules"}
RULES_WITHOUT_SUFFIX = {"Base64Disclosure", "SAMLPassiveScanner", "TechPassiveScanner"}
NOT_RULES = {"ClientPassiveScanRule", "ClientPassiveAbstractScanRule"}


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout


def ported_classes():
    """{(addon, ClassName): [our files]} from the 'Ported from ZAP' headers."""
    found = {}
    for path in (ROOT / "crates").rglob("*.rs"):
        lines = path.read_text(errors="replace").splitlines()[:6]
        head = " ".join(l.removeprefix("//!").strip() for l in lines if l.startswith("//!"))
        m = HEADER.search(head)
        if not m:
            continue
        split = lambda s: [x.strip() for x in re.split(r",| and ", s) if x.strip()]
        classes, addons = split(m.group(1)), split(m.group(2))
        for i, cls in enumerate(classes):
            addon = addons[min(i, len(addons) - 1)]
            # "commonlib AbstractAppFilePlugin", "the `ssti` package (TemplateFormat", "ReflectedSinkPoint)"
            cls = re.search(r"([A-Za-z]\w*)\W*$", cls).group(1)
            found.setdefault((addon, cls), []).append(str(path.relative_to(ROOT)))
    return found


def is_rule(cls):
    return (cls.endswith("ScanRule") or cls in RULES_WITHOUT_SUFFIX) and cls not in NOT_RULES


def unported_rules(tree, ported, skipped):
    """Rules in RULE_ADDONS neither ported from that add-on nor skipped, and the add-ons gone from tree."""
    unported, missing = [], []
    for addon, status in RULE_ADDONS.items():
        informational = addon not in DRIFT_ADDONS
        base = ADDON_JAVA[addon].rsplit("/", 1)[0] + "/"
        names = [t.removeprefix(base) for t in tree if t.startswith(base)]
        if not names:
            missing.append({"addon": addon, "informational": informational})
        for name in names:
            cls = name.removesuffix(".java")
            if "/" not in name and is_rule(cls) and (addon, cls) not in ported and cls not in skipped:
                unported.append({"addon": addon, "class": cls, "status": status, "informational": informational})
    return unported, missing


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", help="existing zap-extensions clone")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    args = ap.parse_args()

    sync = json.loads(SYNC.read_text())
    pinned = sync["commit"]
    if args.repo:
        repo = pathlib.Path(args.repo)
        git(repo, "fetch", "--quiet", "origin", sync.get("branch", "main"))
    else:
        repo = pathlib.Path(tempfile.mkdtemp()) / "zap-extensions"
        subprocess.run(["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout", sync["repository"], str(repo)], check=True)
    head = git(repo, "rev-parse", f"origin/{sync.get('branch', 'main')}").strip()

    report = {"pinned": pinned, "upstream": head, "changed": [], "missing_upstream": [], "data_changed": [], "feed_changed": [], "unported": [], "missing_addons": []}
    ported = ported_classes()
    tree = git(repo, "ls-tree", "-r", "--name-only", head).splitlines()
    for (addon, cls), ours in sorted(ported.items()):
        tmpl = ADDON_JAVA.get(addon)
        if not tmpl:
            continue
        # The class may sit in a subpackage of the add-on (ascanrules/ssti/TemplateFormat.java).
        base = tmpl.rsplit("/", 1)[0] + "/"
        java = tmpl.format(cls)
        if java not in tree:
            java = next((t for t in tree if t.startswith(base) and t.endswith(f"/{cls}.java")), None)
        if not java:
            java = tmpl.format(cls)
            report["missing_upstream"].append({"class": cls, "upstream_path": java, "ours": ours})
            continue
        diff = git(repo, "diff", "--stat", pinned, head, "--", java).strip()
        if diff:
            log = git(repo, "log", "--format=%h %s", f"{pinned}..{head}", "--", java).strip().splitlines()
            report["changed"].append({"class": cls, "upstream_path": java, "ours": ours, "commits": log})

    for data in sync.get("data_files", []):
        if git(repo, "diff", "--stat", pinned, head, "--", data["upstream"]).strip():
            report["data_changed"].append(data)

    # Rules covered by generated feed checks: regenerate when their class or data changes.
    feed_rules = sync.get("feed_rules", {})
    for cls, rule in sorted(feed_rules.items()):
        paths = [ADDON_JAVA[rule["addon"]].format(cls), *rule.get("data", [])]
        log = git(repo, "log", "--format=%h %s", f"{pinned}..{head}", "--", *paths).strip().splitlines()
        if log:
            report["feed_changed"].append({"class": cls, "generator": rule["generator"], "ours": rule["ours"], "commits": log})

    # Upstream rules we haven't ported (or deliberately skipped).
    skipped = set(sync.get("skipped", {})) | set(feed_rules)
    report["unported"], report["missing_addons"] = unported_rules(tree, ported, skipped)

    counted = [x for x in report["unported"] + report["missing_addons"] if not x["informational"]]
    drift = report["changed"] or report["missing_upstream"] or report["data_changed"] or report["feed_changed"] or counted
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"ZAP drift: pinned {pinned[:12]} -> upstream {head[:12]}")
        for c in report["changed"]:
            print(f"\n## Changed upstream: {c['class']}\n  ours: {', '.join(c['ours'])}")
            for line in c["commits"]:
                print(f"  - {line}")
        for c in report["missing_upstream"]:
            print(f"\n## Removed/renamed upstream: {c['class']} ({', '.join(c['ours'])})")
        for d in report["data_changed"]:
            print(f"\n## Data file changed: {d['upstream']} -> {d['ours']}")
        for c in report["feed_changed"]:
            print(f"\n## Feed checks to regenerate: {c['class']} -> {c['ours']} (python3 {c['generator']}, then sign the feed)")
            for line in c["commits"]:
                print(f"  - {line}")
        for a in report["missing_addons"]:
            print(f"\n## Add-on not found upstream: {a['addon']}{' (informational)' if a['informational'] else ''}")
        for title, informational in (("Not ported yet", False), ("Not ported yet, informational (not counted as drift)", True)):
            rules = [u for u in report["unported"] if u["informational"] == informational]
            if rules:
                print(f"\n## {title}:")
            for u in rules:
                print(f"  - {u['addon']}/{u['class']} ({u['status']})")
        if not drift:
            print("No drift.")
    sys.exit(10 if drift else 0)


if __name__ == "__main__":
    main()
