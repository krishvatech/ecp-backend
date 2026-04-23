"""
interactions/ai_pre_event_advisor.py

AI helper for the Pre-Event Q&A Advisor feature.

Operations:
  - check_duplicate_questions(draft, existing_questions) → similarity report

Rules:
  - Uses the same OpenAI key wired up in ai_question_polish.py.
  - Never persists anything.
  - Never auto-merges.  Always returns options for the user to choose from.
  - Timeout: 10 seconds.
  - If AI is unavailable, returns a safe empty result (no crash).
"""

import json
import os

import requests
from django.conf import settings

MAX_INPUT_CHARS = 800
MAX_EXISTING_CHARS = 1500  # total chars budget for existing questions list

_DUPLICATE_SYSTEM_PROMPT = (
    "You are a Q&A duplicate detector for a webinar platform. "
    "Given a new draft question and a list of existing questions (with IDs), "
    "identify which existing questions are semantically similar or duplicates of the draft. "
    "For each match: return the question_id, a brief similarity_reason (1 sentence), "
    "and a suggested_merge (a single cleaner merged phrasing, or null if not applicable). "
    "Only flag high-confidence matches (not just topic overlap). "
    "Return strict JSON: "
    '{\"duplicates\": [{\"question_id\": <int>, \"similarity_reason\": \"...\", \"suggested_merge\": \"...\" or null}]}'
)


def check_duplicate_questions(draft: str, existing_questions: list[dict]) -> dict:
    """
    Compare *draft* against *existing_questions* for semantic similarity.

    Args:
        draft: The new question text the user is composing.
        existing_questions: List of dicts with keys 'id' and 'content'.

    Returns:
        {
          "duplicates": [
            {
              "question_id": <int>,
              "existing_text": <str>,
              "similarity_reason": <str>,
              "suggested_merge": <str|None>,
              "suggestions": ["keep both", "edit existing", "replace existing", "cancel"],
            }
          ],
          "has_duplicates": <bool>,
        }

    On AI error: returns {"duplicates": [], "has_duplicates": False, "error": "..."}
    Raises ValueError only on configuration errors (no API key).
    """
    draft = draft.strip()
    if not draft:
        return {"duplicates": [], "has_duplicates": False}

    if not existing_questions:
        return {"duplicates": [], "has_duplicates": False}

    api_key = getattr(settings, "OPENAI_API_KEY", "") or os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        raise ValueError("OpenAI API key not configured on server.")

    # Build compact representation of existing questions
    existing_parts = []
    char_budget = MAX_EXISTING_CHARS
    for q in existing_questions:
        line = f"[id={q['id']}] {q['content']}"
        if len(line) > char_budget:
            line = line[:char_budget]
        existing_parts.append(line)
        char_budget -= len(line)
        if char_budget <= 0:
            break

    existing_text = "\n".join(existing_parts)

    payload = {
        "model": "gpt-3.5-turbo",
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": _DUPLICATE_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Draft question:\n{draft[:MAX_INPUT_CHARS]}\n\n"
                    f"Existing questions:\n{existing_text}\n\n"
                    "Return JSON: {\"duplicates\": [...]}"
                ),
            },
        ],
        "temperature": 0.1,
        "max_tokens": 600,
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
        return {"duplicates": [], "has_duplicates": False, "error": "AI service timed out."}
    except requests.RequestException as exc:
        return {"duplicates": [], "has_duplicates": False, "error": str(exc)}

    if response.status_code != 200:
        return {
            "duplicates": [],
            "has_duplicates": False,
            "error": f"AI service error {response.status_code}.",
        }

    raw = (
        response.json()
        .get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
    )
    if not raw:
        return {"duplicates": [], "has_duplicates": False}

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {"duplicates": [], "has_duplicates": False, "error": "AI returned non-JSON."}

    raw_duplicates = parsed.get("duplicates", [])

    # Build an id→content lookup for enriching the response
    id_to_content = {q["id"]: q["content"] for q in existing_questions}

    enriched = []
    for dup in raw_duplicates:
        qid = dup.get("question_id")
        if qid is None:
            continue
        enriched.append(
            {
                "question_id": qid,
                "existing_text": id_to_content.get(qid, ""),
                "similarity_reason": dup.get("similarity_reason", ""),
                "suggested_merge": dup.get("suggested_merge") or None,
                # Fixed user-facing action options — never auto-applied
                "suggestions": ["keep both", "edit existing", "replace existing", "cancel"],
            }
        )

    return {
        "duplicates": enriched,
        "has_duplicates": bool(enriched),
    }
