"""Render scan findings as Markdown or a JSON-serializable dict."""

from __future__ import annotations

from datetime import UTC, datetime

from .probes import Finding, Verdict
from .sources import DISCLAIMER, SOURCES

_VERDICT_MARK = {
    Verdict.VULNERABLE: "🔴 VULNERABLE",
    Verdict.RESISTED: "🟢 RESISTED",
    Verdict.INCONCLUSIVE: "🟡 INCONCLUSIVE",
}


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts = {v: 0 for v in Verdict}
    for f in findings:
        counts[f.verdict] += 1
    return {v.value: counts[v] for v in Verdict}


def to_dict(target_label: str, findings: list[Finding]) -> dict:
    return {
        "target": target_label,
        "generated": datetime.now(UTC).isoformat(),
        "summary": summarize(findings),
        "findings": [
            {
                "probe_id": f.probe_id,
                "owasp_id": f.owasp_id,
                "owasp_title": f.owasp_title,
                "name": f.name,
                "verdict": f.verdict.value,
                "response_excerpt": f.response_excerpt,
            }
            for f in findings
        ],
        "disclaimer": DISCLAIMER,
        "sources": SOURCES,
    }


def to_markdown(target_label: str, findings: list[Finding]) -> str:
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    counts = summarize(findings)
    lines: list[str] = []
    lines.append(f"# LLM Red-Team Scan: {target_label}")
    lines.append("")
    lines.append(f"> {DISCLAIMER}")
    lines.append("")
    lines.append(f"**Generated:** {generated}")
    lines.append(
        f"**Summary:** {counts[Verdict.VULNERABLE.value]} vulnerable, "
        f"{counts[Verdict.RESISTED.value]} resisted, "
        f"{counts[Verdict.INCONCLUSIVE.value]} inconclusive "
        f"(of {len(findings)} probes)"
    )
    lines.append("")

    by_category: dict[str, list[Finding]] = {}
    for f in findings:
        by_category.setdefault(f"{f.owasp_id} {f.owasp_title}", []).append(f)

    for category, items in by_category.items():
        lines.append(f"## {category}")
        lines.append("")
        lines.append("| Probe | Verdict | Response excerpt |")
        lines.append("|---|---|---|")
        for f in items:
            excerpt = f.response_excerpt.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {f.name} | {_VERDICT_MARK[f.verdict]} | {excerpt} |")
        lines.append("")

    lines.append("## Sources")
    lines.append("")
    for s in SOURCES:
        lines.append(f"- {s}")
    lines.append("")

    return "\n".join(lines)
