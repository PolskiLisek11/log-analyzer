"""Voice output — the layer that makes it feel like an assistant rather than a log.

Speech synthesis is delegated to whatever the operating system already has, so
there is no dependency to install and nothing to configure. If nothing suitable
is found the agent stays silent and keeps working; a missing TTS binary should
never be the reason a task fails.

Only the final answer is spoken. Reading tool calls aloud is unbearable within
about thirty seconds of trying it.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Protocol

MAX_SPOKEN_CHARS = 700

# Speaking markdown out loud is noise: the listener hears backticks and asterisks
# as pauses and stumbles. Strip the syntax, keep the words.
_CODE_FENCE = re.compile(r"```.*?```", re.DOTALL)
_INLINE_CODE = re.compile(r"`([^`]*)`")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_EMPHASIS = re.compile(r"[*_#>]+")
_BULLET = re.compile(r"^\s*[-*+]\s+", re.MULTILINE)
_WHITESPACE = re.compile(r"\s+")


class Voice(Protocol):
    def speak(self, text: str) -> None: ...
    @property
    def enabled(self) -> bool: ...


def strip_markup(text: str) -> str:
    text = _CODE_FENCE.sub(" (code omitted) ", text or "")
    text = _INLINE_CODE.sub(r"\1", text)
    text = _LINK.sub(r"\1", text)
    text = _BULLET.sub("", text)
    text = _EMPHASIS.sub("", text)
    text = _WHITESPACE.sub(" ", text).strip()

    if len(text) <= MAX_SPOKEN_CHARS:
        return text
    # Cut at a sentence boundary so the last thing heard is a finished thought.
    cut = text[:MAX_SPOKEN_CHARS]
    boundary = max(cut.rfind(". "), cut.rfind("! "), cut.rfind("? "))
    return (cut[: boundary + 1] if boundary > 200 else cut) + " …"


class NullVoice:
    """The default: does nothing, costs nothing."""

    enabled = False

    def speak(self, text: str) -> None:
        return None


class SystemVoice:
    """Speaks through the platform's own TTS binary."""

    # Ordered by preference; the first one present on PATH wins.
    CANDIDATES: tuple[tuple[str, list[str]], ...] = (
        ("say", []),                                   # macOS
        ("espeak-ng", ["-s", "165"]),                  # Linux
        ("espeak", ["-s", "165"]),
        ("spd-say", ["-r", "-10"]),                    # speech-dispatcher
    )

    def __init__(self) -> None:
        self.binary: str | None = None
        self.args: list[str] = []
        for name, args in self.CANDIDATES:
            if shutil.which(name):
                self.binary, self.args = name, args
                break

    @property
    def enabled(self) -> bool:
        return self.binary is not None

    def speak(self, text: str) -> None:
        if not self.enabled:
            return
        spoken = strip_markup(text)
        if not spoken:
            return
        try:
            subprocess.run(  # noqa: S603 — fixed binary, text passed as one argv entry
                [self.binary, *self.args, spoken],
                check=False,
                timeout=90,
                capture_output=True,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            # Losing speech is not worth interrupting the session for.
            return


def make_voice(mode: str) -> Voice:
    """Build the configured voice. Falls back to silence, never raises."""
    if (mode or "off").lower() != "system":
        return NullVoice()
    voice = SystemVoice()
    return voice if voice.enabled else NullVoice()
