from __future__ import annotations

import json
import shutil
from pathlib import Path

import typer

app = typer.Typer(help="Disk usage report utilities.")


@app.command("disk-report")
def disk_report(
    path: str = typer.Option("/", "--path", "-p", help="Path to check (default: /)"),
    warn: int = typer.Option(80, "--warn", help="Warn threshold percent (default: 80)"),
    critical: int = typer.Option(90, "--critical", help="Critical threshold percent (default: 90)"),
    json_out: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """
    Show disk usage for a given path.
    Exit codes:
      0 = OK
      2 = WARN (used >= warn)
      3 = CRITICAL (used >= critical) or invalid path
    """
    p = Path(path)
    if not p.exists():
        typer.echo(f"ERROR: path does not exist: {path}")
        raise typer.Exit(code=3)

    total, used, free = shutil.disk_usage(str(p))
    used_pct = int(round((used / total) * 100)) if total else 0

    status = "OK"
    code = 0
    if used_pct >= critical:
        status = "CRITICAL"
        code = 3
    elif used_pct >= warn:
        status = "WARN"
        code = 2

    payload = {
        "path": str(p),
        "total_bytes": total,
        "used_bytes": used,
        "free_bytes": free,
        "used_percent": used_pct,
        "status": status,
        "warn": warn,
        "critical": critical,
    }

    if json_out:
        typer.echo(json.dumps(payload, ensure_ascii=False))
    else:
        typer.echo(
            f"{status} - {payload['path']} used {used_pct}% "
            f"(used={used}B free={free}B total={total}B) "
            f"thresholds warn={warn}% critical={critical}%"
        )

    raise typer.Exit(code=code)
