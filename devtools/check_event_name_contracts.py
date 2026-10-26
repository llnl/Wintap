#!/usr/bin/env python3
"""Small literal-contract audit, not a full C#/SQL parser.

Check normalized core/EPL network literals and direct ActivityType string
comparisons against the live enum, SQL network literals against the same enum,
and DBT's accepted vocabulary for drift. Raw ETW EventName boundaries are not
normalized consumers. Pass --include-legacy to audit the old Python SQL path too.
"""
import argparse
from pathlib import Path
import re


def enum_names(source):
    body = re.search(r"enum\s+ActivityTypeEnum\s*\{([^}]+)\}", source).group(1)
    return {part.strip().split("=")[0].strip() for part in body.split(",") if part.strip()}


def literal_issues(text, names, sql=False, network_only=False):
    known = {name.lower() for name in names}
    issues = []
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("//", "--", "*")):
            continue
        network_literals = re.findall(r"['\"]((?:tcpip|udpip)[/a-z0-9]*)['\"]", line, re.I)
        for value in network_literals:
            if value.replace("/", "").lower() not in known:
                issues.append((number, f"unknown network literal {value!r}"))
            elif not sql and "/" in value:
                issues.append((number, f"legacy literal {value!r} in normalized consumer"))
        # Explicit equality against IpEvent must not bypass normalization.
        if sql and re.search(r"\bipevent\s*=\s*['\"](?:tcpip|udpip)", line, re.I):
            issues.append((number, "direct IpEvent equality bypasses canonicalization"))
        # General event-domain coverage for direct ActivityType string comparisons.
        if network_only:
            continue
        for value in re.findall(r"\bActivityType(?:\.ToString\(\))?\s*(?:==|!=|=)\s*['\"]([^'\"]+)['\"]", line, re.I):
            if value not in names:
                issues.append((number, f"non-enum ActivityType comparison {value!r}"))
    return issues


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wintap-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--wintappy-root", type=Path)
    parser.add_argument("--include-legacy", action="store_true")
    parser.add_argument("--network-only", action="store_true", help="Limit the gate to network literals; omit for the broader event-domain audit")
    args = parser.parse_args()
    root = args.wintap_root
    names = enum_names((root / "shared/WintapAPI/WintapMessage.cs").read_text())
    files = list((root / "wintap/core").rglob("*.cs")) + list((root / "wintap/core").rglob("*.epl"))
    problems = []
    for path in files:
        for line, reason in literal_issues(path.read_text(), names, network_only=args.network_only):
            problems.append(f"{path}:{line}: {reason}")
    if args.wintappy_root:
        dbt = args.wintappy_root / "wintap_dbt"
        sql_files = list((dbt / "models").rglob("*.sql")) + list((dbt / "tests").rglob("*.sql"))
        if args.include_legacy:
            sql_files.append(args.wintappy_root / "wintappy/datautils/rawtostdview.sql")
        for path in sql_files:
            for line, reason in literal_issues(path.read_text(), names, sql=True):
                problems.append(f"{path}:{line}: {reason}")
        vocabulary = (dbt / "tests/network_activity_names.sql").read_text()
        listed = set(re.findall(r"'((?:tcpip|udpip)[a-z0-9]*)'", vocabulary))
        expected = {n.lower() for n in names if n.startswith(("TcpIp", "UdpIp"))}
        if listed != expected:
            problems.append(f"DBT network vocabulary drift: missing={sorted(expected-listed)}, extra={sorted(listed-expected)}")
    for problem in problems:
        print(problem)
    print(f"Event-name literal audit: {len(problems)} issue(s). Dynamic comparisons and raw producer semantics still need tests/review.")
    return bool(problems)


if __name__ == "__main__":
    raise SystemExit(main())
