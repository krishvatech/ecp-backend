import json
import logging
import os
import requests
from django.conf import settings

logger = logging.getLogger(__name__)

def generate_public_suggestions(
    event_title: str,
    session_title: str,
    context_text: str,
    count: int = 5,
) -> list[dict]:
    """
    Generate candidate questions that a host can publish for attendees to adopt.
    Grounded in the provided context (slides, description, transcript, etc.).
    
    Returns a list of dicts: [
      { "question": "...", "rationale": "...", "confidence_score": 0.9 },
      ...
    ]
    """
    api_key = os.getenv("OPENAI_API_KEY") or getattr(settings, "OPENAI_API_KEY", "")
    if not api_key:
        logger.error("OPENAI_API_KEY not configured for AI public suggestions.")
        raise ValueError("AI API key not configured.")

    if not context_text or not context_text.strip():
        logger.warning("generate_public_suggestions called with empty context.")
        raise ValueError("No context provided for AI suggestions.")

    # System prompt tailored for PUBLIC candidate questions
    system_prompt = (
        "You are an expert event moderator. Your goal is to generate high-quality, "
        "engaging, and relevant questions that attendees might want to ask during a "
        "live webinar or presentation. These questions will be presented to the host "
        "to review and then published to participants to 'adopt' and ask as their own.\n\n"
        "Guidelines:\n"
        "1. GROUNDING: Only generate questions based on the provided presentation context.\n"
        "2. VARIETY: Provide a mix of clarifying, analytical, and forward-looking questions.\n"
        "3. CONCiseness: Questions should be clear and professional (max 200 characters).\n"
        "4. RATIONALE: Briefly explain (max 100 chars) why this question is relevant.\n"
        "5. CONFIDENCE: Provide a confidence score (0.0 to 1.0) for each suggestion.\n\n"
        "Format your output as a strict JSON object:\n"
        "{\n"
        "  \"suggestions\": [\n"
        "    {\"question\": \"...\", \"rationale\": \"...\", \"confidence_score\": 0.95},\n"
        "    ...\n"
        "  ]\n"
        "}"
    )

    user_prompt = f"Event Title: {event_title}\n"
    if session_title:
        user_prompt += f"Session Title: {session_title}\n"
    user_prompt += f"\nPresentation Context:\n{context_text[:8000]}"
    user_prompt += f"\n\nPlease generate {count} candidate questions."

    try:
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4o",  # Using 4o for better quality/speed
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "response_format": {"type": "json_object"},
                "temperature": 0.7,
                "max_tokens": 1000,
            },
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        content = data["choices"][0]["message"]["content"]
        suggestions = json.loads(content).get("suggestions", [])
        
        # Ensure minimal structure
        result = []
        for s in suggestions:
            if s.get("question"):
                result.append({
                    "question": s.get("question"),
                    "rationale": s.get("rationale", ""),
                    "confidence_score": s.get("confidence_score", 0.8),
                })
        return result

    except requests.Timeout:
        logger.error("AI public suggestions timed out.")
        raise ValueError("AI service timed out.")
    except Exception as e:
        logger.exception("AI public suggestions failed: %s", str(e))
        raise ValueError(f"AI service failed: {str(e)}")
