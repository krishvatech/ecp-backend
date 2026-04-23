"""
interactions/ai_question_polish.py

Lightweight AI helper that rewrites a rough Q&A question into a clearer,
more polite, and concise version — without changing its meaning or language.

Rules:
- Uses the same OpenAI provider already wired up in ai_grouping.py.
- Never persists the original or improved draft.
- Preserves the user's original language.
- Keeps the result as a question.
- Does not add facts, names, or details not in the original.
- Timeout: 8 seconds (targets < 2 s P95 for typical short inputs).
"""

import json
import os

import requests
from django.conf import settings

# Max chars passed to AI — guards against expensive / slow prompts.
MAX_INPUT_CHARS = 1000

_SYSTEM_PROMPT = (
    "You improve draft webinar Q&A questions. "
    "Rewrite only for clarity, grammar, concision, and politeness. "
    "Preserve the original meaning and language exactly. "
    "Do not add new facts, names, or details. "
    "Keep it as a question. "
    "Return strict JSON only: {\"improved\": \"...\"}"
)


def polish_question(content: str) -> str:
    """
    Call the OpenAI API to polish *content*.

    Returns the improved question string.
    Raises ValueError on misconfiguration or AI failure so the caller
    can translate it into a friendly HTTP 503.
    """
    content = content.strip()
    if not content:
        raise ValueError("Content must not be empty.")

    api_key = getattr(settings, "OPENAI_API_KEY", "") or os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        raise ValueError("OpenAI API key not configured on server.")

    payload = {
        "model": "gpt-3.5-turbo",
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    "Original question:\n"
                    f"{content[:MAX_INPUT_CHARS]}\n\n"
                    'Return JSON: {"improved": "..."}'
                ),
            },
        ],
        "temperature": 0.3,
        "max_tokens": 300,
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    try:
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=8,  # aggressive timeout to protect latency SLA
        )
    except requests.Timeout:
        raise ValueError("AI service timed out. Please try again.")
    except requests.RequestException as exc:
        raise ValueError(f"Failed to connect to AI service: {exc}")

    if response.status_code != 200:
        error_body = ""
        try:
            err_data = response.json()
            error_body = err_data.get("error", {}).get("message", "") or str(err_data)
        except Exception:
            error_body = response.text[:200]
        raise ValueError(
            f"AI service returned error {response.status_code}"
            + (f": {error_body}" if error_body else ".")
        )


    raw = (
        response.json()
        .get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
    )
    if not raw:
        raise ValueError("Empty response from AI service.")

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"AI returned non-JSON response: {exc}")

    improved = parsed.get("improved", "").strip()
    if not improved:
        raise ValueError("AI did not return an improved question.")

    return improved
