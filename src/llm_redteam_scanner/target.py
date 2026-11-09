"""Thin client for any OpenAI-compatible chat completions endpoint."""

from __future__ import annotations

from dataclasses import dataclass

from openai import APIError, OpenAI


class TargetError(RuntimeError):
    pass


@dataclass
class Target:
    base_url: str
    api_key: str
    model: str
    timeout: float = 30.0

    def __post_init__(self) -> None:
        self._client = OpenAI(base_url=self.base_url, api_key=self.api_key, timeout=self.timeout)

    def send(self, system_prompt: str, user_message: str) -> str:
        try:
            resp = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                temperature=0,
            )
        except APIError as exc:
            raise TargetError(f"Target endpoint error: {exc}") from exc
        except Exception as exc:  # network errors, timeouts, etc.
            raise TargetError(f"Could not reach target endpoint: {exc}") from exc

        choice = resp.choices[0] if resp.choices else None
        content = choice.message.content if choice and choice.message else None
        return content or ""
