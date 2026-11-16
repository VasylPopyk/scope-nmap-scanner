import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from scanner.runner import probe_target
from scanner.validator import parse_scope_file


def test_validator_quarantines_bad_ips(tmp_path: Path):
    targets_file = tmp_path / "targets.txt"
    rejected_file = tmp_path / "rejected.log"
    targets_file.write_text("127.0.0.1\n999.999.999.999\n10.0.0.0/30\ninvalid_host\n")

    valid = parse_scope_file(targets_file, rejected_log=rejected_file)

    assert valid == ["10.0.0.1", "10.0.0.2", "127.0.0.1"]
    assert rejected_file.exists()
    rejected_text = rejected_file.read_text()
    assert "999.999.999.999" in rejected_text
    assert "invalid_host" in rejected_text


@patch("scanner.runner.subprocess.run")
def test_probe_handles_timeout_expired(mock_run):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nmap"], timeout=5)

    res = probe_target("127.0.0.1", timeout=5)

    assert res.status == "timeout"
    assert "Exceeded 5s timeout" in res.error_detail


@patch("scanner.runner.subprocess.run")
def test_probe_handles_called_process_error(mock_run):
    mock_run.side_effect = subprocess.CalledProcessError(
        returncode=1, cmd=["nmap"], stderr="Invalid port specification"
    )

    res = probe_target("127.0.0.1")

    assert res.status == "error"
    assert "Invalid port specification" in res.error_detail


@patch("scanner.runner.subprocess.run")
def test_probe_reraises_file_not_found(mock_run):
    mock_run.side_effect = FileNotFoundError("nmap not found")

    with pytest.raises(FileNotFoundError):
        probe_target("127.0.0.1")