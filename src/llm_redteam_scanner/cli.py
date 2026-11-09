from __future__ import annotations

import json
import os
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import report
from .oracle import new_oracle
from .probes import ALL_PROBES, Verdict
from .scanner import run_scan
from .sources import DISCLAIMER, SOURCES
from .target import Target

app = typer.Typer(
    name="llmscan",
    help="Red-team an OpenAI-compatible LLM endpoint for prompt injection, jailbreaks, "
    "and leakage, mapped to the OWASP Top 10 for LLM Applications (2025).",
    no_args_is_help=True,
)
console = Console()

_VERDICT_STYLE = {
    Verdict.VULNERABLE: "red",
    Verdict.RESISTED: "green",
    Verdict.INCONCLUSIVE: "yellow",
}


@app.command()
def scan(
    base_url: str = typer.Option(..., "--base-url", help="OpenAI-compatible API base URL."),
    model: str = typer.Option(..., "--model", help="Model name to request."),
    api_key: str | None = typer.Option(
        None,
        "--api-key",
        help="API key. Defaults to the OPENAI_API_KEY environment variable if unset.",
    ),
    system_prompt_file: Path | None = typer.Option(
        None,
        "--system-prompt-file",
        help="Your real/representative system prompt. The tool appends a canary secret "
        "to it -- see 'llmscan sources'. Defaults to a generic support-bot prompt.",
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the Markdown report to this file instead of stdout."
    ),
    as_json: bool = typer.Option(False, "--json", help="Print JSON instead of Markdown."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Don't print per-probe progress."),
) -> None:
    """Run every probe against a target endpoint and print or save a report."""
    key = api_key or os.environ.get("OPENAI_API_KEY")
    if not key:
        console.print("[red]Error:[/] no API key. Pass --api-key or set OPENAI_API_KEY.")
        raise typer.Exit(code=1)

    base_prompt = system_prompt_file.read_text() if system_prompt_file else None
    oracle = new_oracle(base_system_prompt=base_prompt)
    target = Target(base_url=base_url, api_key=key, model=model)

    def on_result(finding) -> None:
        if quiet:
            return
        style = _VERDICT_STYLE[finding.verdict]
        console.print(f"[{style}]{finding.verdict.value:12}[/] {finding.owasp_id}  {finding.name}")

    if not quiet:
        console.print(f"Scanning {model} @ {base_url} -- {len(ALL_PROBES)} probes\n")

    findings = run_scan(target, oracle, on_result=on_result)

    if not quiet:
        console.print()

    if as_json:
        text = json.dumps(report.to_dict(f"{model} @ {base_url}", findings), indent=2)
    else:
        text = report.to_markdown(f"{model} @ {base_url}", findings)

    if output:
        output.write_text(text)
        console.print(f"[green]Wrote[/] {output}")
    else:
        # Plain print, not console.print: Rich treats [...] as markup and would
        # mangle JSON (and any report text containing brackets).
        print(text)

    if any(f.verdict == Verdict.VULNERABLE for f in findings):
        raise typer.Exit(code=1)


@app.command(name="list-probes")
def list_probes() -> None:
    """List every probe, its OWASP category, and what it tests."""
    table = Table(title=f"{len(ALL_PROBES)} probes")
    table.add_column("ID")
    table.add_column("OWASP")
    table.add_column("Name")
    table.add_column("Description")
    for p in ALL_PROBES:
        table.add_row(p.id, p.owasp_id, p.name, p.description)
    console.print(table)


@app.command()
def sources() -> None:
    """Print the disclaimer and sources behind this tool's probes."""
    console.print(f"[bold]{DISCLAIMER}[/]\n")
    for s in SOURCES:
        console.print(f"- {s}")


if __name__ == "__main__":
    app()
