"""Static pickle-opcode scanner.

Walks a pickle stream with ``pickletools.genops`` and flags dangerous imports
(``GLOBAL`` / ``STACK_GLOBAL``) and the reduce/build opcodes that would *call* them
on load. It NEVER unpickles, so scanning a malicious file is safe.
"""
from __future__ import annotations

import pickletools

from .models import Finding

# Modules that have no business inside a serialized model and enable code execution.
DANGEROUS_MODULES = {
    "os", "nt", "posix", "subprocess", "sys", "socket", "shutil", "builtins",
    "__builtin__", "runpy", "pty", "commands", "importlib", "ctypes", "code",
    "pdb", "platform", "webbrowser", "multiprocessing", "asyncio", "requests",
    "urllib", "urllib2", "http", "smtplib", "ftplib", "pickle", "operator",
    "functools", "timeit",
}
# Callables that execute code / touch the system, regardless of module.
DANGEROUS_CALLABLES = {
    "system", "popen", "exec", "eval", "__import__", "getattr", "setattr",
    "compile", "call", "check_output", "check_call", "Popen", "run", "spawn",
    "spawnl", "spawnv", "fork", "execv", "execve", "load", "loads", "open",
    "remove", "unlink", "rename", "rmdir", "makedirs", "connect", "urlopen",
    "request", "apply",
}

_STRING_OPS = {
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING", "STRING",
}
_CALL_OPS = {"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"}


def _classify(module: str, attr: str) -> str | None:
    base = module.split(".")[0]
    if base in DANGEROUS_MODULES or attr in DANGEROUS_CALLABLES:
        return "malicious"
    return None


def scan_pickle(data: bytes, stream: str = "") -> tuple[list[Finding], dict]:
    """Return (findings, meta) for one pickle byte stream."""
    findings: list[Finding] = []
    imports: list[tuple[str, str, int]] = []
    recent: list[str] = []
    reduce_count = 0

    try:
        ops = list(pickletools.genops(data))
    except Exception as exc:
        return (
            [Finding("PARSE", "-", 0, "suspicious", f"could not parse pickle: {exc}", stream)],
            {"reduce_count": 0, "imports": []},
        )

    for opcode, arg, pos in ops:
        name = opcode.name
        if name in _STRING_OPS and arg is not None:
            recent.append(arg.decode() if isinstance(arg, bytes) else str(arg))
            recent = recent[-4:]
        elif name == "GLOBAL":
            module, _, attr = str(arg).partition(" ")
            imports.append((module, attr, pos if pos is not None else 0))
        elif name == "STACK_GLOBAL":
            if len(recent) >= 2:
                imports.append((recent[-2], recent[-1], pos if pos is not None else 0))
        elif name in _CALL_OPS:
            reduce_count += 1

    for module, attr, pos in imports:
        severity = _classify(module, attr)
        if severity:
            findings.append(Finding(
                "GLOBAL", f"{module}.{attr}", pos, severity,
                f"imports {module}.{attr} — code-execution capable", stream,
            ))
    return findings, {"reduce_count": reduce_count, "imports": imports}
