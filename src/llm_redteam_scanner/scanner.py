"""Runs every probe against a target and collects findings."""

from __future__ import annotations

from collections.abc import Callable

from .oracle import Oracle
from .probes import ALL_PROBES, Finding, Verdict
from .probes.base import excerpt
from .target import Target, TargetError


def run_scan(
    target: Target,
    oracle: Oracle,
    probes=ALL_PROBES,
    on_result: Callable[[Finding], None] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    system_prompt = oracle.system_prompt

    for probe in probes:
        payload = probe.build_payload(oracle)
        try:
            response = target.send(system_prompt, payload)
            verdict = probe.detect(response, oracle)
            response_excerpt = excerpt(response)
        except TargetError as exc:
            verdict = Verdict.INCONCLUSIVE
            response_excerpt = f"[error contacting target: {exc}]"

        finding = Finding(
            probe_id=probe.id,
            owasp_id=probe.owasp_id,
            owasp_title=probe.owasp_title,
            name=probe.name,
            verdict=verdict,
            response_excerpt=response_excerpt,
        )
        findings.append(finding)
        if on_result:
            on_result(finding)

    return findings
