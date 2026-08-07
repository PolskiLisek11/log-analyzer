"""Jarvis — a personal agent assembled from five parts.

    engine   an AI model                     jarvis/engine.py
    harness  the loop: plan, act, check      jarvis/harness.py
    memory   notes that outlive the process  jarvis/memory.py
    tools    the ability to do actual work   jarvis/tools/
    voice    speech + the terminal interface jarvis/voice.py, jarvis/cli.py

and a home (``~/.jarvis``) where the last four keep their state.

The model alone is a chatbot. The harness is what makes it an agent: it runs the
loop, so the model can plan, act on the world through tools, see what came back,
and keep going until the task is actually finished.

Run it with ``python -m jarvis``. See docs/JARVIS.md for the architecture.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
