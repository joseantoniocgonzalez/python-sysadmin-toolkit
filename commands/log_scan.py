from __future__ import annotations

import csv
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(help="Log analysis utilities (auth/ssh style).")

# Patrones típicos (varían según distro, pero estos cubren muchos casos)
FAILED_PASSWORD_RE = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
PAM_FAILURE_RE = re.compile(r"authentication failure;.*rhost=(?P<ip>\d+\.\d+\.\d+\.\d+).*user=(?P<user>\S*)")

@dataclass
class ScanResult:
    path: str
    total_lines: int
    matched_lines: int
    failed_password: int
    invalid_user: int
    pam_failure: int
    top_ips: list[tuple[str, int]]
    top_users: list[tuple[str, int]]
    pattern: Optional[str]
    pattern_matches: int

def scan_text(text: str, top_n: int = 10, extra_pattern: Optional[re.Pattern[str]] = None) -> ScanResult:
    ip_counter: Counter[str] = Counter()
    user_counter: Counter[str] = Counter()

    total_lines = 0
    matched = 0
    failed_password = 0
    invalid_user = 0
    pam_failure = 0
    pattern_matches = 0

    for line in text.splitlines():
        total_lines += 1

        if extra_pattern and extra_pattern.search(line):
            pattern_matches += 1

        m = FAILED_PASSWORD_RE.search(line)
        if m:
            matched += 1
            failed_password += 1
            ip_counter[m.group("ip")] += 1
            user_counter[m.group("user")] += 1
            continue

        m = INVALID_USER_RE.search(line)
        if m:
            matched += 1
            invalid_user += 1
            ip_counter[m.group("ip")] += 1
            user_counter[m.group("user")] += 1
            continue

        m = PAM_FAILURE_RE.search(line)
        if m:
            matched += 1
            pam_failure += 1
            ip_counter[m.group("ip")] += 1
            u = m.group("user") or "<unknown>"
            user_counter[u] += 1
            continue

    return ScanResult(
        path="",
        total_lines=total_lines,
        matched_lines=matched,
        failed_password=failed_password,
        invalid_user=invalid_user,
        pam_failure=pam_failure,
        top_ips=ip_counter.most_common(top_n),
        top_users=user_counter.most_common(top_n),
        pattern=None,
        pattern_matches=pattern_matches,
    )

def write_json(result: ScanResult, out_path: Path) -> None:
    out_path.write_text(json.dumps(asdict(result), ensure_ascii=False, indent=2), encoding="utf-8")

def write_csv(rows: list[tuple[str, int]], out_path: Path, header: tuple[str, str]) -> None:
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)

@app.command("log-scan")
def log_scan(
    file: str = typer.Option(..., "--file", "-f", help="Path to log file to scan"),
    top: int = typer.Option(10, "--top", help="Top N results (default: 10)"),
    pattern: Optional[str] = typer.Option(None, "--pattern", help="Extra regex pattern to count (e.g. 'Failed password')"),
    json_out: Optional[str] = typer.Option(None, "--json-out", help="Write JSON report to this path"),
    csv_ips: Optional[str] = typer.Option(None, "--csv-ips", help="Write top IPs to CSV path"),
    csv_users: Optional[str] = typer.Option(None, "--csv-users", help="Write top users to CSV path"),
) -> None:
    """
    Scan auth/ssh-style logs and summarize failed login activity.
    Exit codes:
      0 = OK
      3 = file/regex error
    """
    p = Path(file)
    if not p.exists() or not p.is_file():
        typer.echo(f"ERROR: file not found: {file}")
        raise typer.Exit(code=3)

    extra_re: Optional[re.Pattern[str]] = None
    if pattern:
        try:
            extra_re = re.compile(pattern)
        except re.error as e:
            typer.echo(f"ERROR: invalid regex in --pattern: {e}")
            raise typer.Exit(code=3)

    text = p.read_text(encoding="utf-8", errors="replace")
    result = scan_text(text, top_n=top, extra_pattern=extra_re)
    result.path = str(p)
    result.pattern = pattern

    # Salida por consola (resumen)
    typer.echo(f"File: {result.path}")
    typer.echo(f"Lines: {result.total_lines} | Matched: {result.matched_lines}")
    typer.echo(f"Failed password: {result.failed_password} | Invalid user: {result.invalid_user} | PAM failure: {result.pam_failure}")
    if pattern:
        typer.echo(f"Pattern matches: {result.pattern_matches} | Pattern: {pattern}")

    typer.echo("Top IPs:")
    for ip, n in result.top_ips:
        typer.echo(f"  {ip}  {n}")

    typer.echo("Top users:")
    for u, n in result.top_users:
        typer.echo(f"  {u}  {n}")

    # Exports
    if json_out:
        write_json(result, Path(json_out))
    if csv_ips:
        write_csv(result.top_ips, Path(csv_ips), ("ip", "count"))
    if csv_users:
        write_csv(result.top_users, Path(csv_users), ("user", "count"))

    raise typer.Exit(code=0)
