### Versión

~~~bash
mytool version
~~~

### Disco: `disk-report`
Exit codes: `0 OK`, `2 WARN`, `3 CRITICAL/ERROR`

~~~bash
mytool disk disk-report --path /
mytool disk disk-report --path / --warn 80 --critical 90
mytool disk disk-report --path / --json
~~~

### Red: `check-ports`
Exit codes: `0 all OK`, `2 at least one FAIL`, `3 invalid input`

~~~bash
mytool net check-ports --host 127.0.0.1 --ports 22,80,443

mytool net check-ports \
  --host example.com \
  --ports 80,443 \
  --timeout 2
~~~

### Logs: `log-scan`
Resumen de intentos fallidos con top IPs/usuarios.

~~~bash
mytool logs log-scan --file /var/log/auth.log --top 10
~~~

Contar coincidencias de un patrón extra (regex):

~~~bash
mytool logs log-scan \
  --file /var/log/auth.log \
  --pattern "Failed password"
~~~

Export JSON/CSV:

~~~bash
mytool logs log-scan \
  --file tests/data/sample_auth.log \
  --json-out /tmp/report.json \
  --csv-ips /tmp/top_ips.csv \
  --csv-users /tmp/top_users.csv
~~~

### Logs: `log-rate`
Agrupa eventos por ventanas de tiempo (minutos) para detectar picos.

~~~bash
mytool logs log-rate \
  --file tests/data/sample_auth_rate.log \
  --window 10 \
  --top 5
~~~

Export JSON:

~~~bash
mytool logs log-rate \
  --file tests/data/sample_auth_rate.log \
  --window 10 \
  --json-out /tmp/rate.json
~~~

## Tests

~~~bash
pytest -q
~~~

## CI
El workflow de GitHub Actions ejecuta `ruff` y `pytest` (con coverage mínimo) en cada push/PR.

