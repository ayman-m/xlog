"""Caldera command factory with a safe fallback when DSPy is unavailable."""

from __future__ import annotations

import os
from typing import Optional

try:
    import dspy  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    dspy = None


_dspy_configured = False


def _configure_dspy_from_env() -> bool:
    if dspy is None:
        return False

    api_key = os.environ.get("DSPY_API_KEY", "")
    if not api_key:
        return False

    model = os.environ.get("DSPY_MODEL", "gpt-4o")
    temperature = float(os.environ.get("DSPY_TEMPERATURE", "0.5"))
    max_tokens = int(os.environ.get("DSPY_MAX_TOKENS", "10000"))

    lm = dspy.LM(model=model, api_key=api_key, temperature=temperature, max_tokens=max_tokens)
    dspy.configure(lm=lm)
    return True


def create_command_from_description(description: str, platform: str) -> str:
    """
    Build a command string for Caldera abilities.

    Falls back to returning the raw description when DSPy isn't configured.
    """
    global _dspy_configured

    if dspy is None:
        return description

    if not _dspy_configured:
        _dspy_configured = _configure_dspy_from_env()
        if not _dspy_configured:
            return description

    class RankApproaches(dspy.Signature):
        """Rank the approaches to create the command."""

        description: str = dspy.InputField()
        technologies: list[str] = dspy.InputField()
        approaches: list[str] = dspy.OutputField()

    class IdentifyTechnologies(dspy.Signature):
        """
        Identify technologies relevant to the command.
        For windows, the shell interpreter is powershell.exe.
        For linux, the shell interpreter is bash.
        """

        description: str = dspy.InputField()
        platform: str = dspy.InputField()
        technologies: list[str] = dspy.OutputField()

    class CreateFullCommand(dspy.Signature):
        """Create the full command only; no reasoning or tags."""

        technologies: list[str] = dspy.InputField()
        approaches: list[str] = dspy.InputField()
        command: str = dspy.OutputField()

    class CreateCommand(dspy.Module):
        def __init__(self) -> None:
            self.identify_technologies = dspy.ChainOfThought(IdentifyTechnologies)
            self.rank_approaches = dspy.ChainOfThought(RankApproaches)
            self.create_full_command = dspy.ChainOfThought(CreateFullCommand)

        def forward(self, description: str, platform: str) -> str:
            identified = self.identify_technologies(description=description, platform=platform)
            ranked = self.rank_approaches(description=description, technologies=identified)
            full_command = self.create_full_command(technologies=identified, approaches=ranked)
            return full_command.command

    create_command = CreateCommand()
    return create_command(description=description, platform=platform)
