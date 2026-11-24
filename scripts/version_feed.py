#!/usr/bin/env python3
"""Generate the feed's known-vulnerability checks for PHP, Apache httpd and nginx from ZAP's data.

Covers ZAP's ServerSideVersionScanRule (pscanrules, alert 20020, Apache License 2.0)
as signed feed checks instead of a compiled-in port, so new advisories reach installs
without a release. The data is ZAP's php-, apache- and nginx-known-vulnerabilities.json
at the commit zap-sync.json pins for this rule (`feed_rules`, else the ports' `commit`),
or --from DIR holding the three files.

Per product, two passive checks per severity band, so a response gets at most one
finding per band rather than one per CVE; each CVE is a named DSL matcher, listed in the
finding's "Matched:" line. One check is at medium confidence; its twin (`-distribution`)
is at low confidence and reports versions the header marks as a distribution package
(`Apache/2.4.41 (Ubuntu)`, `nginx/1.18.0 (Ubuntu)`, `PHP/7.4.3-4ubuntu2.20`), which
usually has fixes backported,
as ZAP does. CVEs that brainproxy's own rule 100001 (PHP2Shell) already reports are left
out. Unlike ZAP, versions without a patch number (PHP/8.2) aren't matched: ZAP reports
those at low risk, and they match nearly every advisory. ZAP looks for the distribution
in the header that has the version; here it is the header line that has it.

After running it, sign the feed: brainproxy checks feed sign feed --key <key>
"""
import argparse
import json
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
SYNC = ROOT / "zap-sync.json"
RESOURCES = "addOns/pscanrules/src/main/resources/org/zaproxy/zap/extension/pscanrules/resources/"
BANDS = ["critical", "high", "medium", "low"]
VERSION = re.compile(r"^\d+(\.\d+)*$")

PRODUCTS = {
    "php": {
        "data": "php-known-vulnerabilities.json",
        "token": "PHP",
        "title": "PHP",
        "what": "PHP itself",
        "advisories": "PHP's published security advisories",
        # Reported by the built-in PHP2Shell rule (100001) with more specific advice.
        "covered": {"CVE-2026-109618", "CVE-2026-109619"},
        "assumed": "assumed: branch not covered by the advisory",
        "remediation": [
            "Upgrade PHP to a supported version that includes the fixes for the listed",
            "vulnerabilities. Also stop the server disclosing the PHP version: set",
            "expose_php = Off in php.ini and remove version details from the Server header.",
        ],
        "reference": ["https://www.php.net/supported-versions.php", "https://github.com/php/php-src/security/advisories"],
    },
    "apache": {
        "data": "apache-known-vulnerabilities.json",
        "token": "Apache",
        "title": "Apache HTTP Server",
        "what": "Apache HTTP Server itself",
        "advisories": "the Apache HTTP Server project's security advisories",
        "covered": set(),
        "assumed": "assumed: the project lists this version as possibly affected",
        "remediation": [
            "Upgrade Apache HTTP Server to a supported version that includes the fixes for",
            "the listed vulnerabilities. Also stop the server disclosing its version: set",
            "ServerTokens Prod and ServerSignature Off.",
        ],
        "reference": ["https://httpd.apache.org/security/vulnerabilities_24.html", "https://httpd.apache.org/security/"],
    },
    "nginx": {
        "data": "nginx-known-vulnerabilities.json",
        # `nginx/1.25.3` as the Server header has it; `nginx-ingress/1.0` and OpenResty's
        # own version numbers don't match, as in ZAP.
        "token": "nginx",
        "title": "nginx",
        "what": "nginx itself (not third-party modules)",
        "advisories": "the nginx project's security advisories",
        "covered": set(),
        # ZAP marks the advisories that affect only nginx on Windows as assumed.
        "assumed": "assumed: only nginx on Windows is affected",
        "remediation": [
            "Upgrade nginx to a supported version that includes the fixes for the listed",
            "vulnerabilities. Also stop the server disclosing its version: set",
            "server_tokens off.",
        ],
        "reference": ["https://nginx.org/en/security_advisories.html"],
    },
}

# ZAP's distribution markers: a comment naming one, or a package suffix right after the version.
DIST_NAME = (
    r"(?:Debian|Ubuntu|Raspbian|Red ?Hat|RHEL|CentOS|Fedora|Rocky|Alma(?:Linux)?|Oracle|SUSE|openSUSE"
    r"|SLES|Amazon|Gentoo|Mageia|Mint|FreeBSD|OpenBSD|NetBSD)"
)
COMMENT = rf"\([^()]{{0,60}}\b{DIST_NAME}\b[^()]{{0,60}}\)"
SUFFIX = r"-[\w.+~]{0,40}?(?:ubuntu|deb|el\d|fc\d|mga|suse|alpine)"
NUM = r"\d{1,6}\.\d{1,6}\.\d{1,6}"


def load(name, args):
    if args.source:
        return json.loads((pathlib.Path(args.source) / name).read_text())
    sync = json.loads(SYNC.read_text())
    repo = sync["repository"].removeprefix("https://github.com/").removesuffix(".git")
    # The feed may follow upstream data past the ports' pin: moving that pin would pass off
    # ported rules as in sync with upstream code changes they haven't taken.
    pin = sync.get("feed_rules", {}).get("ServerSideVersionScanRule", {}).get("commit", sync["commit"])
    url = f"https://raw.githubusercontent.com/{repo}/{pin}/{RESOURCES}{name}"
    return json.loads(subprocess.run(["curl", "-fsSL", "--max-time", "30", url], check=True, capture_output=True).stdout)


def constraint(rng):
    for v in (rng["introduced"], rng.get("fixed")):
        if v is not None and not VERSION.match(v):
            raise SystemExit(f"unexpected version {v!r} in {rng}")
    parts = [] if rng["introduced"] == "0" else [f">= {rng['introduced']}"]
    if rng.get("fixed"):
        parts.append(f"< {rng['fixed']}")
    if not parts:
        raise SystemExit(f"range matches every version: {rng}")
    return ", ".join(parts)


def dsl(var, ranges):
    return " || ".join(f"compare_versions({var}, '{constraint(r)}')" for r in ranges)


def label(v):
    # Matcher names are joined with ", " in the finding, so keep commas out.
    return f"{v['cve']} {v['name']}".replace(",", ";").strip()


def matchers(p, var, vulns):
    out = []
    for v in sorted(vulns, key=lambda v: (-v.get("cvss", 0), v["cve"])):
        known = [r for r in v["affected"] if not r.get("assumed")]
        assumed = [r for r in v["affected"] if r.get("assumed")]
        if known:
            out.append((label(v), dsl(var, known)))
        if assumed:
            out.append((f"{label(v)} ({p['assumed']})", dsl(var, assumed)))
    return out


def version_dsl(p, distribution):
    """The version from the header line, or nothing when the line's distribution marker says otherwise."""
    at = rf"(?:^|[^\w-]){p['token']}/({NUM})\b"
    if distribution:
        # A suffix right after the version, or a distribution comment after or before it.
        pattern = rf"(?i)^(?:.*?{at}(?:{SUFFIX}.*|.*{COMMENT}.*)|.*{COMMENT}.*?{at}.*|.*)$"
        out = "${1}${2}"
    else:
        pattern = rf"(?i)^(?:.*(?:{COMMENT}|{p['token']}/{NUM}{SUFFIX}).*|.*?{at}.*)$"
        out = "${1}"
    if "'" in pattern:
        raise SystemExit("a quote in the pattern would end the DSL string")
    return f"replace_regex(line, '{pattern}', '{out}')"


def q(s):
    return json.dumps(s, ensure_ascii=False)


def render(key, band, distribution, vulns, updated):
    p = PRODUCTS[key]
    var = key
    cves = ", ".join(sorted(v["cve"] for v in vulns))
    name = f"{p['title']} version with known {band} severity vulnerabilities"
    if distribution:
        name += " (distribution package)"
    description = [
        f"The server disclosed its {p['title']} version in a response header, and that version is",
        f"affected by known {band} severity vulnerabilities in {p['what']}. The matched",
        f"vulnerabilities are listed in the other info; versions are compared against",
        f"{p['advisories']}.",
    ]
    if distribution:
        description += [
            "The header marks the version as a distribution package (a distribution's name in",
            "a comment, or a package suffix after the version). Distributions usually backport",
            "security fixes without changing the version, so some or all of these may already",
            "be fixed: check the package's own advisories before reporting them.",
        ]
    else:
        description += [
            "Some distributions backport security fixes without changing the version number,",
            "so check whether the fixes have been applied before reporting these as confirmed.",
        ]
    description.append(f"Covered: {cves}.")
    suffix = "-distribution" if distribution else ""
    lines = [
        f"# Generated by scripts/version_feed.py from ZAP's {p['data']} ({updated}).",
        "# Covers ZAP ServerSideVersionScanRule (pscanrules, Apache License 2.0). Don't edit by hand.",
        f"id: bp-{key}-known-vulnerabilities-{band}{suffix}",
        "info:",
        f"  name: {q(name)}",
        f"  severity: {band}",
        f"  confidence: {'low' if distribution else 'medium'}",
        "  description: |",
        *(f"    {l}" for l in description),
        "  remediation: |",
        *(f"    {l}" for l in p["remediation"]),
        "  reference:",
        *(f"    - {r}" for r in p["reference"]),
        "  classification:",
        "    cwe-id: CWE-1395",
        f"  tags: {key},cve,version,passive,{band}",
        "scope: passive",
        "http:",
        "  - extractors:",
        "      - type: regex",
        "        name: line",
        "        internal: true",
        "        part: header",
        "        group: 1",
        "        regex:",
        f"          - '(?im)^([^\\r\\n]*(?:^|[^\\w-]){p['token']}/{NUM}\\b[^\\r\\n]*)'",
        "      - type: dsl",
        f"        name: {var}",
        "        dsl:",
        f"          - {q(version_dsl(p, distribution))}",
        "    matchers-condition: or",
        "    matchers:",
    ]
    for mname, expr in matchers(p, var, vulns):
        lines += ["      - type: dsl", f"        name: {q(mname)}", "        dsl:", f"          - {q(expr)}"]
    return "\n".join(lines) + "\n"


def generate(key, args):
    p = PRODUCTS[key]
    data = load(p["data"], args)
    vulns = [v for v in data["vulnerabilities"] if v["cve"] not in p["covered"]]
    unknown = {v["severity"] for v in vulns} - set(BANDS)
    if unknown:
        raise SystemExit(f"{key}: unknown severities {unknown}")
    out = ROOT / "feed" / "passive" / key
    out.mkdir(parents=True, exist_ok=True)
    wanted = set()
    for band in BANDS:
        group = [v for v in vulns if v["severity"] == band]
        if not group:
            continue
        for distribution in (False, True):
            path = out / f"{key}-known-vulnerabilities-{band}{'-distribution' if distribution else ''}.yaml"
            path.write_text(render(key, band, distribution, group, data.get("lastUpdated", "")))
            wanted.add(path.name)
        print(f"{out.relative_to(ROOT)}/{key}-known-vulnerabilities-{band}*.yaml: {len(group)} CVEs")
    for stale in out.glob("*.yaml"):
        if stale.name not in wanted:
            stale.unlink()
            print(f"removed {stale.relative_to(ROOT)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--from", dest="source", help="a folder holding php-, apache- and nginx-known-vulnerabilities.json")
    args = ap.parse_args()
    for key in PRODUCTS:
        generate(key, args)


if __name__ == "__main__":
    main()
