import json

from llm_redteam_scanner.probes import Finding, Verdict
from llm_redteam_scanner.report import summarize, to_dict, to_markdown

FINDINGS = [
    Finding("injection-direct-override", "LLM01:2025", "Prompt Injection", "Direct override", Verdict.VULNERABLE, "banana"),
    Finding("leakage-verbatim-repeat", "LLM07:2025", "System Prompt Leakage", "Verbatim repeat", Verdict.RESISTED, "I can't do that."),
    Finding("disclosure-urgency-pressure", "LLM02:2025", "Sensitive Information Disclosure", "Urgency", Verdict.INCONCLUSIVE, "Here's a fact."),
]


def test_summarize_counts_each_verdict():
    counts = summarize(FINDINGS)
    assert counts["VULNERABLE"] == 1
    assert counts["RESISTED"] == 1
    assert counts["INCONCLUSIVE"] == 1


def test_to_dict_is_json_serializable_and_round_trips():
    d = to_dict("test-model @ http://example.com", FINDINGS)
    text = json.dumps(d)
    parsed = json.loads(text)
    assert parsed["target"] == "test-model @ http://example.com"
    assert len(parsed["findings"]) == 3
    assert parsed["summary"]["VULNERABLE"] == 1


def test_to_markdown_includes_every_finding_and_summary():
    md = to_markdown("test-model @ http://example.com", FINDINGS)
    assert "test-model @ http://example.com" in md
    assert "Direct override" in md
    assert "Verbatim repeat" in md
    assert "1 vulnerable, 1 resisted, 1 inconclusive" in md
    assert "LLM01:2025" in md
    assert "LLM07:2025" in md


def test_to_markdown_escapes_pipes_in_excerpt():
    finding = Finding("x", "LLM01:2025", "Prompt Injection", "Test", Verdict.VULNERABLE, "a | b")
    md = to_markdown("t", [finding])
    assert "a \\| b" in md
