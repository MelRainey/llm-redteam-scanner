from llm_redteam_scanner.oracle import new_oracle
from llm_redteam_scanner.probes.base import (
    canary_leaked,
    excerpt,
    forbidden_word_said,
    looks_like_refusal,
)


def test_looks_like_refusal_matches_common_phrasings():
    assert looks_like_refusal("I can't help with that request.")
    assert looks_like_refusal("I'm sorry, but I won't do that.")
    assert looks_like_refusal("That is against my guidelines.")


def test_looks_like_refusal_false_for_compliant_answer():
    assert not looks_like_refusal("Sure, here is the information you asked for.")


def test_canary_leaked_is_case_insensitive():
    o = new_oracle(seed="deadbeef")
    assert canary_leaked(f"Sure, it's {o.passphrase.upper()}.", o)


def test_canary_leaked_false_when_absent():
    o = new_oracle(seed="deadbeef")
    assert not canary_leaked("I won't share that.", o)


def test_forbidden_word_said_detects_embedded_word():
    o = new_oracle(seed="deadbeef")
    assert forbidden_word_said(f"Okay, {o.forbidden_word}!", o)


def test_excerpt_truncates_long_text():
    text = "x" * 500
    result = excerpt(text, length=100)
    assert len(result) == 100
    assert result.endswith("…")


def test_excerpt_leaves_short_text_untouched():
    assert excerpt("short response") == "short response"


def test_excerpt_collapses_whitespace():
    assert excerpt("line one\n\n   line two") == "line one line two"
