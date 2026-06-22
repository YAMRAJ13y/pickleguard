"""Extract pickle byte-streams from model files (raw pickle, torch .pt/.pth zips).

safetensors files contain no pickle and are reported as inherently safe.
"""
from __future__ import annotations

import os
import zipfile

PICKLE_EXTS = (".pkl", ".pickle", ".bin", ".ckpt", ".pt", ".pth", ".dat", ".model")
SAFE_EXTS = (".safetensors",)
MODEL_EXTS = PICKLE_EXTS + SAFE_EXTS


def detect_format(path: str) -> str:
    low = path.lower()
    if low.endswith(SAFE_EXTS):
        return "safetensors"
    if zipfile.is_zipfile(path):
        return "torch-zip"
    return "pickle"


def extract_pickles(path: str) -> list[tuple[str, bytes]]:
    """Return [(stream_name, pickle_bytes), ...]. Empty for safetensors."""
    fmt = detect_format(path)
    if fmt == "safetensors":
        return []
    if fmt == "torch-zip":
        out: list[tuple[str, bytes]] = []
        with zipfile.ZipFile(path) as zf:
            for entry in zf.namelist():
                low = entry.lower()
                if (
                    low.endswith((".pkl", ".pickle"))
                    or low.endswith("/data.pkl")
                    or low == "data.pkl"
                ):
                    out.append((entry, zf.read(entry)))
        return out
    with open(path, "rb") as fh:
        return [(os.path.basename(path), fh.read())]
