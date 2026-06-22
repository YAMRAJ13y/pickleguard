"""Core data models for PickleGuard."""
from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_RANK = {"safe": 0, "low": 1, "suspicious": 2, "malicious": 3}
VERDICT_RANK = {"safe": 0, "suspicious": 1, "malicious": 2, "error": 1}


@dataclass
class Finding:
    opcode: str  # GLOBAL | STACK_GLOBAL | REDUCE | PARSE
    symbol: str  # e.g. "os.system"
    position: int  # byte offset in the pickle stream
    severity: str  # malicious | suspicious | low
    reason: str
    stream: str = ""  # which embedded pickle (for .pt/.pth archives)


@dataclass
class ModelReport:
    path: str
    fmt: str  # pickle | torch-zip | safetensors | unknown
    sha256: str = ""
    verdict: str = "safe"  # safe | suspicious | malicious | error
    findings: list[Finding] = field(default_factory=list)
    reduce_count: int = 0
    dangerous_imports: list[str] = field(default_factory=list)
    recommendation: str = ""
    error: str | None = None
