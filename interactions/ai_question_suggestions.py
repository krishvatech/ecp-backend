"""
interactions/ai_question_suggestions.py

Lightweight AI helper that privately suggests 2–3 thoughtful audience
questions for a webinar attendee based on provided presentation context.

Rules:
- Uses the same OpenAI provider already wired up in ai_question_polish.py.
- Never persists generated suggestions.
- Grounded only in supplied context; does not invent facts.
- Timeout: 10 seconds.
- Max context chars: 4000 (truncated if longer).
"""

import json
import os
import uuid

import requests
from django.conf import settings

# Max chars of presentation context passed to AI.
MAX_CONTEXT_CHARS = 4000

_SYSTEM_PROMPT = (
    "You generate private Q&A question suggestions for a webinar attendee. "
    "Use only the provided presentation context. "
    "Do not invent facts, names, or claims not present in the context. "
    "Create concise, clear questions that a curious attendee might genuinely ask. "
    "Avoid generic filler questions. "
    "Preserve the language of the context if obvious. "
    "Return strict JSON only — no markdown, no commentary."
)


def suggest_questions(
    event_title: str,
    session_title: str,
    context_text: str,
    count: int = 3,
) -> list[dict]:
    """
    Call the OpenAI API to generate private Q&A question suggestions.

    Args:
        event_title:   Title of the event.
        session_title: Title of the current session (may be empty).
        context_text:  Concatenated presentation context (slides, agenda, …).
        count:         Desired number of suggestions (capped at 3).

    Returns:
        A list of dicts, each with 'question' and 'reason' keys.

    Raises:
        ValueError on misconfiguration or AI failure so the caller can
        translate it into a friendly HTTP 503.
    """
    count = max(1, min(3, count))
    context_text = (context_text or "").strip()
    if not context_text:
        raise ValueError("No presentation context available.")

    api_key = getattr(settings, "OPENAI_API_KEY", "") or os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        raise ValueError("OpenAI API key not configured on server.")

    user_prompt = (
        f"Event title: {event_title or 'Unknown'}\n"
        f"Session title: {session_title or 'General session'}\n\n"
        f"Presentation context:\n{context_text[:MAX_CONTEXT_CHARS]}\n\n"
        f"Generate exactly {count} thoughtful audience questions.\n"
        "Return JSON in this exact format:\n"
        '{"suggestions": [{"question": "...", "reason": "..."}, ...]}'
    )

    payload = {
        "model": "gpt-3.5-turbo",
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.5,
        "max_tokens": 500,
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
            timeout=10,
        )
    except requests.Timeout:
        raise ValueError("AI service timed out. Please try again.")
    except requests.RequestException as exc:
        raise ValueError(f"Failed to connect to AI service: {exc}")

    if response.status_code != 200:
        raise ValueError(f"AI service returned error {response.status_code}.")

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

    suggestions_raw = parsed.get("suggestions", [])
    if not isinstance(suggestions_raw, list):
        raise ValueError("AI returned unexpected suggestions format.")

    # Normalise: add a local id, ensure keys present
    suggestions = []
    for item in suggestions_raw[:3]:
        question = (item.get("question") or "").strip()
        reason = (item.get("reason") or "").strip()
        if question:
            suggestions.append({
                "id": str(uuid.uuid4()),
                "question": question,
                "reason": reason,
            })

    if not suggestions:
        raise ValueError("AI did not return any question suggestions.")

    return suggestions
