"""Generate PickleGuard test fixtures (committed to fixtures/).

These pickles are INERT demonstrations: building them with ``pickle.dumps`` only
*serializes* the reduce instructions — nothing is executed here, and PickleGuard
scans them statically without unpickling. The payloads are harmless (``echo``).

Run:  python scripts/build_fixtures.py
"""
from __future__ import annotations

import pathlib
import pickle
import struct
import zipfile

OUT = pathlib.Path(__file__).resolve().parent.parent / "fixtures"
OUT.mkdir(exist_ok=True)

# 1) benign: pure data, no GLOBAL/REDUCE
benign = pickle.dumps({"weights": [0.1, 0.2, 0.3], "name": "demo-model", "epochs": 3}, protocol=4)
(OUT / "benign.pkl").write_bytes(benign)


class _EvilOS:
    def __reduce__(self):
        import os
        return (os.system, ("echo pwned",))


class _EvilEval:
    def __reduce__(self):
        return (eval, ("1+1",))


evil_os = pickle.dumps(_EvilOS(), protocol=4)
(OUT / "malicious_os_system.pkl").write_bytes(evil_os)
(OUT / "malicious_eval.pkl").write_bytes(pickle.dumps(_EvilEval(), protocol=4))

# 2) hand-assembled posix.system payload — a module alias a minimal {os,subprocess}
#    denylist would miss, but PickleGuard's broader module set catches.
_payload = b"echo pwned"
bypass = (
    b"\x80\x04"            # PROTO 4
    b"cposix\nsystem\n"    # GLOBAL posix system
    b"("                   # MARK
    b"\x8c" + bytes([len(_payload)]) + _payload  # SHORT_BINUNICODE 'echo pwned'
    + b"tR."               # TUPLE, REDUCE, STOP
)
(OUT / "malicious_posix_bypass.pkl").write_bytes(bypass)


def _zip_model(name: str, pickle_bytes: bytes) -> None:
    with zipfile.ZipFile(OUT / name, "w") as zf:
        zf.writestr("archive/data.pkl", pickle_bytes)


# 3) torch-style .pt archives (zip containing archive/data.pkl)
_zip_model("model_safe.pt", benign)
_zip_model("model_evil.pt", evil_os)

# 4) minimal safetensors: 8-byte little-endian header length + JSON header
_header = b"{}"
(OUT / "model.safetensors").write_bytes(struct.pack("<Q", len(_header)) + _header)

print(f"fixtures written to {OUT}")
