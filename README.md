# python-sysadmin-toolkit

CLI de utilidades pequeñas para tareas de sysadmin/ops, hecha en Python con Typer y tests con pytest.

## Requisitos
- Python 3.10+
- Linux/macOS

## Instalación (modo desarrollo)

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install -U pip
    python -m pip install -e ".[dev]"

## Uso

### Versión

    mytool version

### Disco: `disk-report`
Exit codes: `0 OK`, `2 WARN`, `3 CRITICAL/ERROR`

    mytool disk disk-report --path /
    mytool disk disk-report --path / --warn 80 --critical 90
    mytool disk disk-report --path / --json

### Red: `check-ports`
Exit codes: `0 all OK`, `2 at least one FAIL`, `3 invalid input`

    mytool net check-ports --host 127.0.0.1 --ports 22,80,443
    mytool net check-ports --host example.com --ports 80,443 --timeout 2

### Logs: `log-scan`
Resumen de intentos fallidos con top IPs/usuarios.

    mytool logs log-scan --file /var/log/auth.log --top 10

Contar coincidencias de un patrón extra (regex):

    mytool logs log-scan --file /var/log/auth.log --pattern "Failed password"

Export JSON/CSV:

    mytool logs log-scan --file tests/data/sample_auth.log \
      --json-out /tmp/report.json \
      --csv-ips /tmp/top_ips.csv \
      --csv-users /tmp/top_users.csv

### Logs: `log-rate`
Agrupa eventos por ventanas de tiempo (minutos) para detectar picos.

    mytool logs log-rate --file tests/data/sample_auth_rate.log --window 10 --top 5

Export JSON:

    mytool logs log-rate --file tests/data/sample_auth_rate.log --window 10 --json-out /tmp/rate.json

## Tests

    pytest -q

## CI
El workflow de GitHub Actions ejecuta `pytest` en cada push/PR (matriz de Python 3.11–3.13).

