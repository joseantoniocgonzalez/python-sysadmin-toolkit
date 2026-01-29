from typer.testing import CliRunner
import json
from pathlib import Path

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


def test_log_scan_file_not_found():
    r = runner.invoke(app, ["logs", "log-scan", "--file", "/no/existe.log"])
    assert r.exit_code == 3
    assert "file not found" in r.stdout.lower()


def test_log_scan_counts_and_top():
    r = runner.invoke(
        app, ["logs", "log-scan", "--file", "tests/data/sample_auth.log", "--top", "2"]
    )
    assert r.exit_code == 0
    out = r.stdout.lower()
    assert "failed password: 3" in out
    assert "invalid user: 1" in out
    assert "pam failure: 1" in out
    # top ip 203.0.113.10 aparece 3 veces en failed password
    assert "203.0.113.10" in r.stdout




def test_log_scan_exports_json_and_csv(tmp_path: Path):
    out_json = tmp_path / "report.json"
    out_ips = tmp_path / "ips.csv"
    out_users = tmp_path / "users.csv"

    r = runner.invoke(
        app,
        [
            "logs",
            "log-scan",
            "--file",
            "tests/data/sample_auth.log",
            "--top",
            "3",
            "--pattern",
            "Failed password",
            "--json-out",
            str(out_json),
            "--csv-ips",
            str(out_ips),
            "--csv-users",
            str(out_users),
        ],
    )
    assert r.exit_code == 0

    assert out_json.exists()
    assert out_ips.exists()
    assert out_users.exists()

    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["failed_password"] == 3
    assert data["pattern_matches"] == 3
    assert data["pattern"] == "Failed password"

    ips_lines = out_ips.read_text(encoding="utf-8").splitlines()
    assert ips_lines[0] == "ip,count"
    assert any("203.0.113.10,3" in line for line in ips_lines[1:])

    users_lines = out_users.read_text(encoding="utf-8").splitlines()
    assert users_lines[0] == "user,count"
    assert any("root,2" in line for line in users_lines[1:])


def test_log_scan_invalid_regex_pattern():
    r = runner.invoke(
        app, ["logs", "log-scan", "--file", "tests/data/sample_auth.log", "--pattern", "["]
    )
    assert r.exit_code == 3
    assert "invalid regex" in r.stdout.lower()


def test_log_rate_invalid_window():
    r = runner.invoke(
        app, ["logs", "log-rate", "--file", "tests/data/sample_auth_rate.log", "--window", "0"]
    )
    assert r.exit_code == 3
    assert "window must be > 0" in r.stdout.lower()


def test_log_rate_buckets_default_10min():
    r = runner.invoke(
        app,
        [
            "logs",
            "log-rate",
            "--file",
            "tests/data/sample_auth_rate.log",
            "--window",
            "10",
            "--top",
            "5",
        ],
    )
    assert r.exit_code == 0
    out = r.stdout
    # En ventana 00:00 hay 3 eventos (00:00:01, 00:05:00, 00:09:59)
    assert "2000-01-01T00:00" in out
    assert "2000-01-01T00:10" in out
    # el primer bucket debería tener 3
    assert "2000-01-01T00:00  3" in out


def test_log_rate_json_export(tmp_path):
    out_json = tmp_path / "rate.json"
    r = runner.invoke(
        app,
        [
            "logs",
            "log-rate",
            "--file",
            "tests/data/sample_auth_rate.log",
            "--window",
            "10",
            "--json-out",
            str(out_json),
        ],
    )
    assert r.exit_code == 0
    assert out_json.exists()
