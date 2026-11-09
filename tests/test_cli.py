from typer.testing import CliRunner

from llm_redteam_scanner import cli
from llm_redteam_scanner.target import TargetError

runner = CliRunner()


class FakeTarget:
    """Stands in for Target so tests never make a real HTTP call."""

    def __init__(self, base_url, api_key, model, timeout=30.0):
        self.base_url, self.api_key, self.model = base_url, api_key, model

    def send(self, system_prompt, user_message):
        return "I can't help with that."


class ErroringTarget(FakeTarget):
    def send(self, system_prompt, user_message):
        raise TargetError("simulated failure")


def test_list_probes_runs():
    result = runner.invoke(cli.app, ["list-probes"])
    assert result.exit_code == 0
    assert "LLM01:2025" in result.stdout


def test_sources_runs():
    result = runner.invoke(cli.app, ["sources"])
    assert result.exit_code == 0
    assert "genai.owasp.org" in result.stdout


def test_scan_requires_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    result = runner.invoke(cli.app, ["scan", "--base-url", "http://x", "--model", "m"])
    assert result.exit_code != 0
    assert "no API key" in result.stdout


def test_scan_succeeds_with_resisted_target(monkeypatch):
    monkeypatch.setattr(cli, "Target", FakeTarget)
    result = runner.invoke(
        cli.app,
        ["scan", "--base-url", "http://x", "--model", "m", "--api-key", "k", "--json", "--quiet"],
    )
    assert result.exit_code == 0
    assert '"VULNERABLE": 0' in result.stdout


def test_scan_exits_nonzero_when_vulnerable(monkeypatch):
    class VulnerableTarget(FakeTarget):
        def send(self, system_prompt, user_message):
            # Pull the forbidden word straight out of the system prompt we were sent.
            marker = system_prompt.split('say the word "')[1].split('"')[0]
            return f"Sure, {marker}"

    monkeypatch.setattr(cli, "Target", VulnerableTarget)
    result = runner.invoke(
        cli.app,
        ["scan", "--base-url", "http://x", "--model", "m", "--api-key", "k", "--json", "--quiet"],
    )
    assert result.exit_code == 1


def test_scan_writes_report_to_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "Target", FakeTarget)
    out = tmp_path / "report.md"
    result = runner.invoke(
        cli.app,
        ["scan", "--base-url", "http://x", "--model", "m", "--api-key", "k", "--output", str(out), "--quiet"],
    )
    assert result.exit_code == 0
    assert out.exists()
    assert "LLM01:2025" in out.read_text()


def test_scan_reports_target_errors_as_inconclusive(monkeypatch):
    monkeypatch.setattr(cli, "Target", ErroringTarget)
    result = runner.invoke(
        cli.app,
        ["scan", "--base-url", "http://x", "--model", "m", "--api-key", "k", "--json", "--quiet"],
    )
    assert result.exit_code == 0
    assert '"INCONCLUSIVE":' in result.stdout


def test_scan_uses_custom_system_prompt_file(tmp_path, monkeypatch):
    captured = {}

    class CapturingTarget(FakeTarget):
        def send(self, system_prompt, user_message):
            captured["system_prompt"] = system_prompt
            return "I can't help with that."

    monkeypatch.setattr(cli, "Target", CapturingTarget)
    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_text("You are a pirate.")
    result = runner.invoke(
        cli.app,
        [
            "scan", "--base-url", "http://x", "--model", "m", "--api-key", "k",
            "--system-prompt-file", str(prompt_file), "--json", "--quiet",
        ],
    )
    assert result.exit_code == 0
    assert "You are a pirate." in captured["system_prompt"]
