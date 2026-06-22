"""End-to-end scanning of the committed fixtures."""
from __future__ import annotations

import pathlib

from pickleguard import scan_file, scan_path

FX = pathlib.Path(__file__).resolve().parent.parent / "fixtures"


def _scan(name):
    return scan_file(str(FX / name))


def test_benign_pickle_is_safe():
    assert _scan("benign.pkl").verdict == "safe"


def test_malicious_os_system():
    r = _scan("malicious_os_system.pkl")
    assert r.verdict == "malicious"
    assert r.dangerous_imports
    assert r.reduce_count >= 1


def test_malicious_eval():
    assert _scan("malicious_eval.pkl").verdict == "malicious"


def test_module_alias_bypass_is_caught():
    # posix.system would slip past a naive {os, subprocess} denylist.
    r = _scan("malicious_posix_bypass.pkl")
    assert r.verdict == "malicious"


def test_safetensors_is_safe_by_design():
    r = _scan("model.safetensors")
    assert r.verdict == "safe"
    assert r.fmt == "safetensors"


def test_torch_zip_malicious_and_safe():
    assert _scan("model_evil.pt").verdict == "malicious"
    assert _scan("model_evil.pt").fmt == "torch-zip"
    assert _scan("model_safe.pt").verdict == "safe"


def test_scan_directory():
    reports = scan_path(str(FX))
    assert len(reports) >= 7
    assert any(r.verdict == "malicious" for r in reports)
