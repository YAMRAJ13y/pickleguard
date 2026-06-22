"""Render scan results (a list of ModelReport) to JSON and markdown, with an SBOM."""
from __future__ import annotations

from .models import VERDICT_RANK, ModelReport

_ICON = {"malicious": "🔴", "suspicious": "🟠", "safe": "🟢", "error": "⚪"}


def to_dict(reports: list[ModelReport]) -> dict:
    summary = {"safe": 0, "suspicious": 0, "malicious": 0, "error": 0}
    for r in reports:
        summary[r.verdict] = summary.get(r.verdict, 0) + 1
    return {
        "scanner": {"name": "PickleGuard", "rulesetVersion": "1.0"},
        "scanned": len(reports),
        "summary": summary,
        "models": [
            {
                "path": r.path,
                "format": r.fmt,
                "sha256": r.sha256,
                "verdict": r.verdict,
                "reduceCount": r.reduce_count,
                "dangerousImports": r.dangerous_imports,
                "recommendation": r.recommendation,
                "error": r.error,
                "findings": [
                    {
                        "opcode": f.opcode,
                        "symbol": f.symbol,
                        "position": f.position,
                        "severity": f.severity,
                        "reason": f.reason,
                        "stream": f.stream,
                    }
                    for f in r.findings
                ],
            }
            for r in reports
        ],
    }


def to_markdown(reports: list[ModelReport]) -> str:
    summary = {"safe": 0, "suspicious": 0, "malicious": 0, "error": 0}
    for r in reports:
        summary[r.verdict] = summary.get(r.verdict, 0) + 1
    lines = [
        "# PickleGuard — Model Scan Report",
        "",
        f"**Scanned:** {len(reports)} file(s) — "
        f"🔴 {summary['malicious']} malicious · 🟠 {summary['suspicious']} suspicious · "
        f"🟢 {summary['safe']} safe",
        "",
    ]
    for r in sorted(reports, key=lambda x: -VERDICT_RANK.get(x.verdict, 0)):
        icon = _ICON.get(r.verdict, "•")
        lines += [
            f"### {icon} `{r.path}` — {r.verdict.upper()}  ({r.fmt})",
            f"- **sha256:** `{r.sha256[:16]}…`  ·  **reduce/call opcodes:** {r.reduce_count}",
        ]
        if r.dangerous_imports:
            lines.append(f"- **Dangerous imports:** {', '.join(r.dangerous_imports)}")
        for f in r.findings:
            where = f" in `{f.stream}`" if f.stream else ""
            lines.append(f"  - `{f.opcode}` {f.symbol} @ {f.position}{where} — {f.reason}")
        if r.error:
            lines.append(f"- **Note:** {r.error}")
        lines.append(f"- **Recommend:** {r.recommendation}")
        lines.append("")
    return "\n".join(lines)
