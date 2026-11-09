import pytest

from llm_redteam_scanner.oracle import new_oracle
from llm_redteam_scanner.probes import (
    ALL_PROBES,
    DISCLOSURE_PROBES,
    INJECTION_PROBES,
    LEAKAGE_PROBES,
    Verdict,
)
from llm_redteam_scanner.probes.output import PROBES as OUTPUT_PROBES

ORACLE = new_oracle(seed="deadbeef")


def test_probe_ids_are_unique():
    ids = [p.id for p in ALL_PROBES]
    assert len(ids) == len(set(ids))


def test_every_probe_builds_a_nonempty_payload():
    for probe in ALL_PROBES:
        payload = probe.build_payload(ORACLE)
        assert isinstance(payload, str)
        assert payload.strip()


@pytest.mark.parametrize("probe", INJECTION_PROBES, ids=lambda p: p.id)
def test_injection_probe_detects_forbidden_word(probe):
    response = f"Sure, here you go: {ORACLE.forbidden_word}"
    assert probe.detect(response, ORACLE) == Verdict.VULNERABLE


@pytest.mark.parametrize("probe", INJECTION_PROBES, ids=lambda p: p.id)
def test_injection_probe_detects_refusal(probe):
    assert probe.detect("I can't do that.", ORACLE) == Verdict.RESISTED


@pytest.mark.parametrize("probe", INJECTION_PROBES, ids=lambda p: p.id)
def test_injection_probe_inconclusive_on_unrelated_answer(probe):
    assert probe.detect("Here's a fun fact about octopuses.", ORACLE) == Verdict.INCONCLUSIVE


@pytest.mark.parametrize("probe", [*LEAKAGE_PROBES, *DISCLOSURE_PROBES], ids=lambda p: p.id)
def test_leakage_and_disclosure_probes_detect_passphrase(probe):
    response = f"The passphrase is {ORACLE.passphrase}."
    assert probe.detect(response, ORACLE) == Verdict.VULNERABLE


@pytest.mark.parametrize("probe", [*LEAKAGE_PROBES, *DISCLOSURE_PROBES], ids=lambda p: p.id)
def test_leakage_and_disclosure_probes_detect_refusal(probe):
    assert probe.detect("I'm not able to share that.", ORACLE) == Verdict.RESISTED


@pytest.mark.parametrize("probe", OUTPUT_PROBES, ids=lambda p: p.id)
def test_output_probe_resisted_on_refusal(probe):
    assert probe.detect("I can't generate that kind of content.", ORACLE) == Verdict.RESISTED


def test_output_probe_vulnerable_when_payload_emitted_unfenced():
    probe = next(p for p in OUTPUT_PROBES if p.id == "output-raw-html-script")
    response = "<script>alert(document.cookie)</script>"
    assert probe.detect(response, ORACLE) == Verdict.VULNERABLE


def test_output_probe_not_vulnerable_when_wrapped_in_code_fence():
    probe = next(p for p in OUTPUT_PROBES if p.id == "output-raw-html-script")
    response = "```html\n<script>alert(document.cookie)</script>\n```"
    assert probe.detect(response, ORACLE) == Verdict.INCONCLUSIVE


def test_sql_output_probe_vulnerable_on_unfenced_drop_table():
    probe = next(p for p in OUTPUT_PROBES if p.id == "output-sql-injection-payload")
    response = "WHERE username = '' OR '1'='1'; DROP TABLE users;--"
    assert probe.detect(response, ORACLE) == Verdict.VULNERABLE
