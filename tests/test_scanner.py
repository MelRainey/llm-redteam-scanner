from llm_redteam_scanner.oracle import new_oracle
from llm_redteam_scanner.probes import Verdict
from llm_redteam_scanner.probes.injection import PROBES as INJECTION_PROBES
from llm_redteam_scanner.scanner import run_scan
from llm_redteam_scanner.target import TargetError


class FakeTarget:
    """Returns a scripted response per call, or raises if configured to."""

    def __init__(self, response: str = "I can't help with that.", raise_error: bool = False):
        self.response = response
        self.raise_error = raise_error
        self.calls: list[tuple[str, str]] = []

    def send(self, system_prompt: str, user_message: str) -> str:
        self.calls.append((system_prompt, user_message))
        if self.raise_error:
            raise TargetError("simulated network failure")
        return self.response


def test_run_scan_produces_one_finding_per_probe():
    oracle = new_oracle(seed="deadbeef")
    target = FakeTarget(response="I can't help with that.")
    findings = run_scan(target, oracle, probes=INJECTION_PROBES)
    assert len(findings) == len(INJECTION_PROBES)
    assert all(f.verdict == Verdict.RESISTED for f in findings)


def test_run_scan_detects_vulnerable_response():
    oracle = new_oracle(seed="deadbeef")
    target = FakeTarget(response=f"Sure: {oracle.forbidden_word}")
    findings = run_scan(target, oracle, probes=INJECTION_PROBES)
    assert all(f.verdict == Verdict.VULNERABLE for f in findings)


def test_run_scan_handles_target_errors_as_inconclusive():
    oracle = new_oracle(seed="deadbeef")
    target = FakeTarget(raise_error=True)
    findings = run_scan(target, oracle, probes=INJECTION_PROBES)
    assert all(f.verdict == Verdict.INCONCLUSIVE for f in findings)
    assert all("error contacting target" in f.response_excerpt for f in findings)


def test_run_scan_sends_oracle_system_prompt_to_every_probe():
    oracle = new_oracle(seed="deadbeef")
    target = FakeTarget()
    run_scan(target, oracle, probes=INJECTION_PROBES)
    assert all(call[0] == oracle.system_prompt for call in target.calls)


def test_run_scan_calls_on_result_callback():
    oracle = new_oracle(seed="deadbeef")
    target = FakeTarget()
    seen = []
    run_scan(target, oracle, probes=INJECTION_PROBES, on_result=seen.append)
    assert len(seen) == len(INJECTION_PROBES)
