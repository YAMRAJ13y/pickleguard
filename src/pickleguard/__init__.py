"""PickleGuard - statically detect malicious pickle opcodes in ML model files.

Walks pickle/torch (.pt/.pth) streams with pickletools and flags dangerous imports
(os/subprocess/builtins.eval ...) and the reduce opcodes that invoke them on load —
WITHOUT unpickling, so scanning a malicious model is safe. safetensors is reported
as safe by design.

Public API:
    scan_file(path) -> ModelReport
    scan_path(path) -> list[ModelReport]      (file or directory)
    to_dict(reports) / to_markdown(reports)
    scan_pickle(data) in pickleguard.scanner  (low-level opcode scan)
"""
from __future__ import annotations

from .engine import scan_file, scan_path
from .models import Finding, ModelReport
from .report import to_dict, to_markdown

__version__ = "0.1.0"

__all__ = [
    "scan_file",
    "scan_path",
    "ModelReport",
    "Finding",
    "to_dict",
    "to_markdown",
    "__version__",
]
