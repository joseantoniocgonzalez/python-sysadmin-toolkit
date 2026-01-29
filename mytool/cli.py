from __future__ import annotations

import typer

from commands.disk_report import app as disk_app
from commands.check_ports import app as net_app

app = typer.Typer(help="python-sysadmin-toolkit: small ops/sysadmin CLI utilities")

# Montamos subcomandos en un grupo "disk"
app.add_typer(disk_app, name="disk")
app.add_typer(net_app, name="net")

@app.command("version")
def version() -> None:
    typer.echo("mytool 0.1.0")
