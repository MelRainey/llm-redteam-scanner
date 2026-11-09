"""Citations and the disclaimer shown on every report."""

DISCLAIMER = (
    "Findings are heuristic (keyword/refusal-pattern matching against a known canary "
    "secret), not a guarantee of safety or exploitability. A RESISTED verdict means this "
    "probe didn't leak the canary or trip a known refusal pattern -- it does not mean the "
    "target is safe against prompt injection generally, only against this specific probe. "
    "An INCONCLUSIVE verdict means the response didn't clearly match either outcome and "
    "deserves a manual look. Only run this against systems you own or have explicit "
    "authorization to test."
)

SOURCES = [
    "OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/",
    "LLM01:2025 Prompt Injection: https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    "LLM02:2025 Sensitive Information Disclosure: https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
    "LLM05:2025 Improper Output Handling: https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
    "LLM07:2025 System Prompt Leakage: https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/",
]
