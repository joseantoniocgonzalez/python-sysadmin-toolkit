from typer.testing import CliRunner

from mytool.cli import app

runner = CliRunner()

def test_version_ok():
    r = runner.invoke(app, ["version"])
    assert r.exit_code == 0
    assert "mytool" in r.stdout

def test_disk_report_invalid_path_is_critical():
    r = runner.invoke(app, ["disk", "disk-report", "--path", "/this/path/should/not/exist"])
    assert r.exit_code == 3
    assert "does not exist" in r.stdout.lower()

def test_disk_report_json_outputs_json():
    r = runner.invoke(app, ["disk", "disk-report", "--path", "/", "--json"])
    assert r.exit_code in (0, 2, 3)  # depende del uso real del disco
    assert r.stdout.strip().startswith("{")
    assert '"used_percent"' in r.stdout

def test_check_ports_invalid_input():
    r = runner.invoke(app, ["net", "check-ports", "--ports", ""])
    assert r.exit_code == 3
    assert "invalid" in r.stdout.lower()

def test_check_ports_invalid_input():
    r = runner.invoke(app, ["net", "check-ports", "--ports", ""])
    assert r.exit_code == 3
    assert "invalid" in r.stdout.lower()

def test_log_scan_file_not_found():
    r = runner.invoke(app, ["logs", "log-scan", "--file", "/no/existe.log"])
    assert r.exit_code == 3
    assert "file not found" in r.stdout.lower()

def test_log_scan_counts_and_top():
    r = runner.invoke(app, ["logs", "log-scan", "--file", "tests/data/sample_auth.log", "--top", "2"])
    assert r.exit_code == 0
    out = r.stdout.lower()
    assert "failed password: 3" in out
    assert "invalid user: 1" in out
    assert "pam failure: 1" in out
    # top ip 203.0.113.10 aparece 3 veces en failed password
    assert "203.0.113.10" in r.stdout
