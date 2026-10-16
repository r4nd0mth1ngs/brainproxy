#!/usr/bin/env python3
"""Report upstream changes to the ZAP rules brainproxy has ported.

Every ported rule file starts with a header like
    //! Ported from ZAP CrlfInjectionScanRule (ascanrules, Apache License 2.0).
This script finds those headers, maps each to its Java file in zaproxy/zap-extensions,
and compares the pinned commit (zap-sync.json) with upstream HEAD. It also lists rules
that exist upstream but are not ported yet, and changes to the data files we copied.

Usage: scripts/zap_drift.py [--repo PATH_TO_ZAP_EXTENSIONS_CLONE] [--json]
Without --repo it clones zap-extensions (blobless, sparse) into a temp dir.
Exit code 0: no drift; 10: drift found (report printed); other: error.
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
    "commonlib": "addOns/commonlib/src/main/java/org/zaproxy/addon/commonlib/{}.java",
}


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
            found.setdefault((addon, cls), []).append(str(path.relative_to(ROOT)))
    return found


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

    report = {"pinned": pinned, "upstream": head, "changed": [], "missing_upstream": [], "data_changed": [], "unported": []}
    ported = ported_classes()
    for (addon, cls), ours in sorted(ported.items()):
        tmpl = ADDON_JAVA.get(addon)
        if not tmpl:
            continue
        java = tmpl.format(cls)
        exists = subprocess.run(["git", "-C", str(repo), "cat-file", "-e", f"{head}:{java}"], capture_output=True).returncode == 0
        if not exists:
            report["missing_upstream"].append({"class": cls, "upstream_path": java, "ours": ours})
            continue
        diff = git(repo, "diff", "--stat", pinned, head, "--", java).strip()
        if diff:
            log = git(repo, "log", "--format=%h %s", f"{pinned}..{head}", "--", java).strip().splitlines()
            report["changed"].append({"class": cls, "upstream_path": java, "ours": ours, "commits": log})

    for data in sync.get("data_files", []):
        if git(repo, "diff", "--stat", pinned, head, "--", data["upstream"]).strip():
            report["data_changed"].append(data)

    # Upstream release rules we haven't ported (or deliberately skipped).
    skipped = set(sync.get("skipped", {}))
    ported_names = {cls for (_, cls) in ported}
    for addon in ("pscanrules", "ascanrules"):
        listing = git(repo, "ls-tree", "--name-only", f"{head}:{ADDON_JAVA[addon].rsplit('/', 1)[0]}")
        for name in listing.split():
            cls = name.removesuffix(".java")
            if cls.endswith("ScanRule") and cls not in ported_names and cls not in skipped:
                report["unported"].append({"addon": addon, "class": cls})

    drift = report["changed"] or report["missing_upstream"] or report["data_changed"] or report["unported"]
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
        if report["unported"]:
            print("\n## Not ported yet:")
            for u in report["unported"]:
                print(f"  - {u['addon']}/{u['class']}")
        if not drift:
            print("No drift.")
    sys.exit(10 if drift else 0)


if __name__ == "__main__":
    main()
