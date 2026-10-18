"""Shared Groq LLM helper for specialist agents.

Falls back gracefully when GROQ_API_KEY is missing so unit tests
and offline demos continue to work.
"""

from __future__ import annotations

import os
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

_GROQ_AVAILABLE = False
_client = None

try:
    from groq import Groq

    api_key = os.getenv("GROQ_API_KEY")
    if api_key and api_key != "your_key_here":
        _client = Groq(api_key=api_key)
        _GROQ_AVAILABLE = True
except Exception:
    _GROQ_AVAILABLE = False
    _client = None


def llm_available() -> bool:
    """Return True when a usable Groq client is configured."""
    return _GROQ_AVAILABLE and _client is not None


def ask_llm(system_prompt: str, user_prompt: str, model: str = "llama-3.1-8b-instant") -> Optional[str]:
    """
    Send a prompt to Groq and return the text response.
    Returns None when the LLM is unavailable or the call fails.
    """
    if not llm_available():
        return None

    try:
        completion = _client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
            max_tokens=400,
        )
        return completion.choices[0].message.content.strip()
    except Exception:
        return None
