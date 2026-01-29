from __future__ import annotations

import socket
from dataclasses import dataclass

import typer

app = typer.Typer(help="Network port checks.")


@dataclass
class CheckResult:
    host: str
    port: int
    ok: bool
    error: str | None = None


def tcp_check(host: str, port: int, timeout: float = 1.0) -> CheckResult:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return CheckResult(host=host, port=port, ok=True)
    except OSError as e:
        return CheckResult(host=host, port=port, ok=False, error=str(e))


@app.command("check-ports")
def check_ports(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host to check"),
    ports: str = typer.Option(
        "22,80,443", "--ports", "-p", help="Comma-separated ports, e.g. 22,80,443"
    ),
    timeout: float = typer.Option(1.0, "--timeout", help="TCP connect timeout seconds"),
) -> None:
    """
    Check if TCP ports are reachable on a host.
    Exit codes:
      0 = all OK
      2 = at least one FAILED
      3 = invalid input
    """
    try:
        port_list = [int(x.strip()) for x in ports.split(",") if x.strip()]
        if not port_list:
            raise ValueError("empty ports")
    except ValueError:
        typer.echo("ERROR: invalid --ports value. Example: --ports 22,80,443")
        raise typer.Exit(code=3) from None

    any_fail = False
    for port in port_list:
        r = tcp_check(host, port, timeout=timeout)
        if r.ok:
            typer.echo(f"OK {r.host}:{r.port}")
        else:
            any_fail = True
            typer.echo(f"FAIL {r.host}:{r.port} - {r.error}")

    raise typer.Exit(code=2 if any_fail else 0)
