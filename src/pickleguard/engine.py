"""Scan model files/directories and classify each as safe / suspicious / malicious."""
from __future__ import annotations

import hashlib
import os

from .loaders import MODEL_EXTS, detect_format, extract_pickles
from .models import ModelReport
from .scanner import scan_pickle


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_file(path: str) -> ModelReport:
    fmt = detect_format(path)
    report = ModelReport(path=path, fmt=fmt, sha256=_sha256(path))

    if fmt == "safetensors":
        report.verdict = "safe"
        report.recommendation = "safetensors stores only tensors — no pickle. Safe by design."
        return report

    try:
        streams = extract_pickles(path)
    except Exception as exc:
        report.verdict = "error"
        report.error = str(exc)
        return report

    if not streams:
        report.verdict = "suspicious"
        report.error = "no pickle stream found in archive"
        return report

    for name, data in streams:
        findings, meta = scan_pickle(data, stream=name)
        report.findings.extend(findings)
        report.reduce_count += meta["reduce_count"]

    report.dangerous_imports = sorted({f.symbol for f in report.findings if f.opcode == "GLOBAL"})
    dangerous = [f for f in report.findings if f.severity == "malicious"]
    parse_errors = [f for f in report.findings if f.opcode == "PARSE"]

    if dangerous and report.reduce_count > 0:
        report.verdict = "malicious"
        report.recommendation = (
            "DO NOT load. Dangerous imports are invoked on unpickle. Re-serialize as "
            "safetensors and treat the source as compromised."
        )
    elif dangerous:
        report.verdict = "suspicious"
        report.recommendation = (
            "Dangerous imports present without an obvious call — inspect before loading; "
            "prefer safetensors."
        )
    elif parse_errors:
        report.verdict = "suspicious"
        report.recommendation = "Unparseable pickle — do not load untrusted files."
    else:
        report.verdict = "safe"
        report.recommendation = "No dangerous opcodes found. Prefer safetensors for distribution."
    return report


def scan_path(path: str) -> list[ModelReport]:
    if os.path.isdir(path):
        reports: list[ModelReport] = []
        for root, _, files in os.walk(path):
            for fn in sorted(files):
                if fn.lower().endswith(MODEL_EXTS):
                    reports.append(scan_file(os.path.join(root, fn)))
        return reports
    return [scan_file(path)]
