# python-sysadmin-toolkit

CLI de utilidades pequeñas para tareas de sysadmin/ops, hecha en Python con Typer y tests con pytest.

## Requisitos
- Python 3.10+
- Linux/macOS (Windows posible con ajustes menores)

## Instalación (modo desarrollo)

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install -U pip
    python -m pip install -e ".[dev]"

## Uso

### Versión

    python -m mytool version

### Disco: `disk-report`
Exit codes: `0 OK`, `2 WARN`, `3 CRITICAL/ERROR`

    python -m mytool disk disk-report --path /
    python -m mytool disk disk-report --path / --warn 80 --critical 90
    python -m mytool disk disk-report --path / --json

### Red: `check-ports`
Exit codes: `0 all OK`, `2 at least one FAIL`, `3 invalid input`

    python -m mytool net check-ports --host 127.0.0.1 --ports 22,80,443
    python -m mytool net check-ports --host example.com --ports 80,443 --timeout 2

## Tests

    pytest -q

## Roadmap
- [ ] `log-scan` (búsqueda de patrones en logs + export JSON/CSV)
- [ ] Logging / `--verbose`
- [ ] Empaquetado como comando instalable (entrypoint)
