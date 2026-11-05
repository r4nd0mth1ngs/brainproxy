#!/usr/bin/env python3
"""Rebuilds the built-in fuzzer wordlists in crates/core/src/wordlists/data/.

Each list is assembled from upstream files pinned to a commit, cleaned (CRLF, blank and
duplicate lines, comment lines where the upstream file uses them, destructive SQL/NoSQL/OS
statements in payload lists), and written with a MANIFEST.json recording sources, commits,
licenses, and sha256 of each output. Licenses and attributions are in NOTICE.

Usage: scripts/update-wordlists.py   (needs curl and access to raw.githubusercontent.com)
Bump a commit in SOURCES, rerun, review the diff, and update NOTICE if a source changes.
Downloaded files are only read as text; nothing from them is executed.
"""

import hashlib
import json
import re
import sys
import subprocess
import urllib.parse
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "crates/core/src/wordlists/data"

SOURCES = {
    "seclists": ("danielmiessler/SecLists", "c23b603128ed21e46164a0afd357f0c242135f41", "MIT"),
    "patt": ("swisskyrepo/PayloadsAllTheThings", "3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a", "MIT"),
    "fuzzdb": ("fuzzdb-project/fuzzdb", "5656ab25dc6bb43bae32236fab775658a90d7380", "BSD-3-Clause / CC-BY-3.0"),
    "param-miner": ("PortSwigger/param-miner", "e43e3b16be11117ed67cfde60e80acf2e95a4adc", "Apache-2.0"),
    "blns": ("minimaxir/big-list-of-naughty-strings", "db33ec7b1d5d9616a88c76394b7d0897bd0b97eb", "MIT"),
    "fuzz.txt": ("Bo0oM/fuzz.txt", "8512da9892c1f88b5a62b958bec4a6b2974d66ed", "WTFPL"),
}

# Short probes written for brainproxy (Apache-2.0), put first in their lists.
OWN = {
    "sqli": ["'", '"', "''", "\\", "')", '")', "'))", "' --", "' #", "';", "' AND '1'='1", "' AND '1'='2", "1 AND 1=1", "1 AND 1=2"],
}

# Statements that change or destroy data, or run commands beyond a harmless probe.
DESTRUCTIVE = re.compile(
    r"(?i)(\bdrop\s+(table|database)\b|\btruncate\b|\bdelete\s+from\b|\bxp_cmdshell\b|\bshutdown\b"
    r"|\binsert\s+into\b|\bupdate\s+\S+\s+set\b|\.(insert|remove|drop|update)\s*\(|\brm\s+-rf\b"
    r"|\bsp_msforeachtable\b|\bdbms_\w+\b)"
)

# name: (description, caution or None, payload list?, [(source, path, options)])
LISTS = {
    "sqli": (
        "SQL injection: quotes, operators, comments, error-based payloads, and polyglots",
        "OR-true payloads (' or 1=1--) can change every row if the parameter reaches an UPDATE or DELETE",
        True,
        [
            ("seclists", "Fuzzing/Databases/SQLi/quick-SQLi.txt", {}),
            ("patt", "SQL Injection/Intruder/Generic_ErrorBased.txt", {}),
            ("seclists", "Fuzzing/Databases/SQLi/SQLi-Polyglots.txt", {}),
        ],
    ),
    "sqli-time": (
        "Time-based blind SQL injection (sleep, benchmark, waitfor); look for slow responses",
        "each hit makes the server wait; keep concurrency low",
        True,
        # The source leaves the delay as __TIME__ for its tool to fill in; the fuzzer sends
        # payloads as they are, so give it a delay that stands out: 5 seconds.
        [("seclists", "Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt", {"replace": {"__TIME__": "5"}, "comments": True})],
    ),
    "sqli-login-bypass": (
        "SQL injection login bypass for username/password fields",
        None,
        True,
        [("seclists", "Fuzzing/Databases/SQLi/sqli.auth.bypass.txt", {})],
    ),
    "xss": (
        "Cross-site scripting: tags, event handlers, and polyglots; look for the payload reflected unencoded",
        None,
        True,
        [
            ("seclists", "Fuzzing/XSS/robot-friendly/XSS-BruteLogic.txt", {}),
            ("seclists", "Fuzzing/XSS/Polyglots/XSS-Polyglots.txt", {}),
            ("patt", "XSS Injection/Intruders/xss_payloads_quick.txt", {}),
        ],
    ),
    "path-traversal": (
        "Path traversal and file inclusion (../, encodings, /etc/passwd, win.ini)",
        None,
        True,
        [
            ("patt", "Directory Traversal/Intruder/directory_traversal.txt", {}),
            ("patt", "File Inclusion/Intruders/simple-check.txt", {}),
        ],
    ),
    "command-injection": (
        "OS command injection with harmless commands (id, cat /etc/passwd) and separators",
        None,
        True,
        [
            ("patt", "Command Injection/Intruder/command-execution-unix.txt", {}),
            ("fuzzdb", "attack/os-cmd-execution/command-injection-template.txt", {"replace": {"{cmd}": "id"}}),
        ],
    ),
    "ssti": (
        "Server-side template injection: expressions that evaluate to 1764 (42*42) in common engines",
        None,
        True,
        [("seclists", "Fuzzing/template-engines-expression.txt", {})],
    ),
    "nosqli": (
        "NoSQL injection (MongoDB operators and JavaScript)",
        None,
        True,
        [
            ("patt", "NoSQL Injection/Intruder/NoSQL.txt", {}),
            ("patt", "NoSQL Injection/Intruder/MongoDB.txt", {}),
        ],
    ),
    "naughty-strings": (
        "Strings that often break input handling: unicode, emoji, RTL, format strings, reserved words",
        None,
        True,
        [("blns", "blns.txt", {"comments": True})],
    ),
    "special-chars": (
        "Single special characters, to see which ones a parameter mishandles",
        None,
        True,
        [("seclists", "Fuzzing/special-chars.txt", {})],
    ),
    "content-discovery": (
        "Paths worth checking on any web server: VCS and config files, backups, admin panels, debug endpoints",
        "send with GET only: some endpoints (e.g. /actuator/shutdown) act on POST",
        False,
        [("fuzz.txt", "fuzz.txt", {})],
    ),
    "parameters": (
        "Common parameter names, for finding hidden parameters",
        None,
        False,
        [("param-miner", "resources/params", {})],
    ),
    "headers": (
        "Common request header names, for header fuzzing",
        None,
        False,
        [("param-miner", "resources/headers", {})],
    ),
    "usernames": (
        "Most common usernames (root, admin, test, ...)",
        None,
        False,
        [("seclists", "Usernames/top-usernames-shortlist.txt", {})],
    ),
    "passwords": (
        "The 1,000 most common passwords",
        "password guessing can lock accounts; check the engagement rules",
        False,
        [("seclists", "Passwords/Common-Credentials/xato-net-10-million-passwords-1000.txt", {})],
    ),
    "http-methods": (
        "HTTP methods, including WebDAV and nonstandard ones",
        "includes DELETE, PUT, and other state-changing methods",
        False,
        [("seclists", "Fuzzing/http-request-methods.txt", {})],
    ),
    "extensions": (
        "Common file extensions (with the leading dot)",
        None,
        False,
        [("seclists", "Fuzzing/extensions-most-common.fuzz.txt", {})],
    ),
}


def fetch(source, path):
    repo, commit, _ = SOURCES[source]
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/{urllib.parse.quote(path)}"
    # curl uses the system trust store (python.org builds often have no CA bundle).
    out = subprocess.run(["curl", "-fsSL", "--max-time", "60", url], check=True, capture_output=True).stdout
    return out.decode("utf-8", errors="replace")


def build(name, payload, parts):
    lines, seen, dropped = [], set(), 0
    for line in OWN.get(name, []):
        seen.add(line)
        lines.append(line)
    for source, path, opts in parts:
        # Split on \n only: payloads may contain U+2028, form feeds, and similar on purpose.
        for line in fetch(source, path).split("\n"):
            line = line.rstrip("\r")
            for k, v in opts.get("replace", {}).items():
                line = line.replace(k, v)
            if not line.strip() or (opts.get("comments") and line.startswith("#")):
                continue
            if payload and DESTRUCTIVE.search(line):
                dropped += 1
                continue
            if line not in seen:
                seen.add(line)
                lines.append(line)
    return lines, dropped


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = {"sources": {}, "lists": {}}
    for key, (repo, commit, lic) in SOURCES.items():
        manifest["sources"][key] = {"repo": f"https://github.com/{repo}", "commit": commit, "license": lic}
    manifest["sources"]["brainproxy"] = {"repo": "https://github.com/r4nd0mth1ngs/brainproxy", "commit": None, "license": "Apache-2.0"}
    for name, (desc, caution, payload, parts) in LISTS.items():
        lines, dropped = build(name, payload, parts)
        data = ("\n".join(lines) + "\n").encode()
        (OUT / f"{name}.txt").write_bytes(data)
        manifest["lists"][name] = {
            "description": desc,
            "caution": caution,
            "count": len(lines),
            "dropped_destructive": dropped,
            "sources": ([{"source": "brainproxy", "path": "scripts/update-wordlists.py"}] if name in OWN else [])
            + [{"source": s, "path": p} for s, p, _ in parts],
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        print(f"{name:20} {len(lines):6} lines  {len(data):7} bytes  dropped {dropped}", file=sys.stderr)
    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
