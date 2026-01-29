from __future__ import annotations

import importlib.metadata

import typer

from commands.check_ports import app as net_app
from commands.disk_report import app as disk_app
from commands.log_scan import app as logs_app

app = typer.Typer(help="python-sysadmin-toolkit: small ops/sysadmin CLI utilities")

# Montamos subcomandos en un grupo "disk"
app.add_typer(disk_app, name="disk")
app.add_typer(net_app, name="net")
app.add_typer(logs_app, name="logs")


@app.command("version")
def version() -> None:
    name = "python-sysadmin-toolkit"
    typer.echo(f"mytool {importlib.metadata.version(name)}")
