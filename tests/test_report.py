"""Report + SBOM serialization."""
from __future__ import annotations

import json
import pathlib

from pickleguard import scan_path, to_dict, to_markdown

FX = pathlib.Path(__file__).resolve().parent.parent / "fixtures"


def test_to_dict_round_trips():
    reports = scan_path(str(FX))
    d = to_dict(reports)
    assert d["summary"]["malicious"] >= 3
    assert d["scanned"] == len(reports)
    assert all("sha256" in m for m in d["models"])
    json.loads(json.dumps(d))


def test_to_markdown():
    reports = scan_path(str(FX))
    md = to_markdown(reports)
    assert "# PickleGuard" in md
    assert "MALICIOUS" in md
