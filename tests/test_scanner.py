"""Low-level opcode scanner unit tests."""
from __future__ import annotations

import pickle

from pickleguard.scanner import scan_pickle


def test_benign_data_has_no_findings():
    findings, meta = scan_pickle(pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
    assert findings == []
    assert meta["reduce_count"] == 0


def test_detects_eval_reduce():
    class _Evil:
        def __reduce__(self):
            return (eval, ("1+1",))

    findings, meta = scan_pickle(pickle.dumps(_Evil(), protocol=4))
    assert any(f.severity == "malicious" for f in findings)
    assert meta["reduce_count"] >= 1


def test_parse_error_is_flagged():
    findings, _ = scan_pickle(b"not a pickle at all")
    assert findings and findings[0].opcode == "PARSE"
