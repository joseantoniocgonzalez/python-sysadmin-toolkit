from __future__ import annotations

import csv
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

import typer

app = typer.Typer(help="Log analysis utilities (auth/ssh style).")

# Patrones típicos (varían según distro, pero estos cubren muchos casos)
FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
PAM_FAILURE_RE = re.compile(
    r"authentication failure;.*rhost=(?P<ip>\d+\.\d+\.\d+\.\d+).*user=(?P<user>\S*)"
)

# Timestamp syslog: "Jan 01 00:00:01 ..."
TS_RE = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})")

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


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
    pattern: str | None
    pattern_matches: int


@dataclass
class RateResult:
    path: str
    window_minutes: int
    matched_events: int
    buckets: list[tuple[str, int]]  # (bucket_start_iso, count)
    top_ips: list[tuple[str, int]]  # (ip, count)


def parse_syslog_timestamp(line: str) -> datetime | None:
    """
    Parse syslog timestamps like: 'Jan  1 00:00:01' or 'Jan 01 00:00:01'
    Syslog no incluye año, usamos un año fijo para análisis reproducible.
    """
    m = TS_RE.search(line)
    if not m:
        return None
    mon = MONTHS.get(m.group("mon"))
    if not mon:
        return None
    day = int(m.group("day"))
    hh, mm, ss = (int(x) for x in m.group("time").split(":"))
    return datetime(2000, mon, day, hh, mm, ss)


def floor_to_window(dt: datetime, window_minutes: int) -> datetime:
    # baja al inicio de la ventana: minuto múltiplo de window_minutes
    minute = (dt.minute // window_minutes) * window_minutes
    return dt.replace(minute=minute, second=0, microsecond=0)


def scan_text(
    text: str, top_n: int = 10, extra_pattern: re.Pattern[str] | None = None
) -> ScanResult:
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


def write_json(obj, out_path: Path) -> None:
    out_path.write_text(json.dumps(asdict(obj), ensure_ascii=False, indent=2), encoding="utf-8")


def write_csv(rows: list[tuple[str, int]], out_path: Path, header: tuple[str, str]) -> None:
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


@app.command("log-scan")
def log_scan(
    file: str = typer.Option(..., "--file", "-f", help="Path to log file to scan"),
    top: int = typer.Option(10, "--top", help="Top N results (default: 10)"),
    pattern: str | None = typer.Option(
        None, "--pattern", help="Extra regex pattern to count (e.g. 'Failed password')"
    ),
    json_out: str | None = typer.Option(None, "--json-out", help="Write JSON report to this path"),
    csv_ips: str | None = typer.Option(None, "--csv-ips", help="Write top IPs to CSV path"),
    csv_users: str | None = typer.Option(None, "--csv-users", help="Write top users to CSV path"),
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

    extra_re: re.Pattern[str] | None = None
    if pattern:
        try:
            extra_re = re.compile(pattern)
        except re.error as e:
            typer.echo(f"ERROR: invalid regex in --pattern: {e}")
            raise typer.Exit(code=3) from None

    text = p.read_text(encoding="utf-8", errors="replace")
    result = scan_text(text, top_n=top, extra_pattern=extra_re)
    result.path = str(p)
    result.pattern = pattern

    # Salida por consola (resumen)
    typer.echo(f"File: {result.path}")
    typer.echo(f"Lines: {result.total_lines} | Matched: {result.matched_lines}")
    typer.echo(
        f"Failed password: {result.failed_password} | Invalid user: {result.invalid_user} | PAM failure: {result.pam_failure}"
    )
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


@app.command("log-rate")
def log_rate(
    file: str = typer.Option(..., "--file", "-f", help="Path to log file to analyze"),
    window: int = typer.Option(10, "--window", help="Window size in minutes (default: 10)"),
    top: int = typer.Option(5, "--top", help="Top N time windows to show (default: 5)"),
    json_out: str | None = typer.Option(None, "--json-out", help="Write JSON report to this path"),
) -> None:
    """
    Group failed-login events into time windows and show the busiest windows.
    Counts only lines matching: Failed password / Invalid user / PAM auth failure.

    Exit codes:
      0 = OK
      3 = file/format error
    """
    if window <= 0:
        typer.echo("ERROR: --window must be > 0")
        raise typer.Exit(code=3)

    p = Path(file)
    if not p.exists() or not p.is_file():
        typer.echo(f"ERROR: file not found: {file}")
        raise typer.Exit(code=3)

    text = p.read_text(encoding="utf-8", errors="replace")

    bucket_counts: Counter[str] = Counter()
    ip_counter: Counter[str] = Counter()
    matched_events = 0

    for line in text.splitlines():
        # solo contamos eventos de interés
        ip = None
        if m := FAILED_PASSWORD_RE.search(line):
            ip = m.group("ip")
        elif m := INVALID_USER_RE.search(line):
            ip = m.group("ip")
        elif m := PAM_FAILURE_RE.search(line):
            ip = m.group("ip")

        if not ip:
            continue

        ts = parse_syslog_timestamp(line)
        if ts is None:
            # si no podemos parsear la fecha, no lo metemos en rate
            continue

        matched_events += 1
        ip_counter[ip] += 1
        b = floor_to_window(ts, window)
        bucket_counts[b.isoformat(timespec="minutes")] += 1

    buckets = bucket_counts.most_common(top)

    result = RateResult(
        path=str(p),
        window_minutes=window,
        matched_events=matched_events,
        buckets=buckets,
        top_ips=ip_counter.most_common(10),
    )

    typer.echo(f"File: {result.path}")
    typer.echo(f"Window: {window} minutes | Matched events: {matched_events}")
    typer.echo("Top windows:")
    if not buckets:
        typer.echo("  (no parsable events)")
    else:
        for b, n in buckets:
            typer.echo(f"  {b}  {n}")

    typer.echo("Top IPs:")
    for ip, n in result.top_ips[:5]:
        typer.echo(f"  {ip}  {n}")

    if json_out:
        write_json(result, Path(json_out))

    raise typer.Exit(code=0)
