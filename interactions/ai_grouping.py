import json
import requests
import os
import logging
from django.conf import settings
from .models import Question, QnAQuestionGroupSuggestion

logger = logging.getLogger(__name__)

def suggest_groups(event_id, user):
    """
    Fetches questions for an event and uses an AI service to suggest groups.
    Excludes seed questions and questions already in a group.
    """
    logger.info(f"[AI-GROUPING] Starting suggest_groups for event {event_id}")

    questions = Question.objects.filter(
        event_id=event_id,
        is_hidden=False,
        is_seed=False,
        moderation_status__in=["approved", "pending"],
    ).exclude(group_membership__isnull=False)

    logger.info(f"[AI-GROUPING] Found {questions.count()} questions to group")

    q_data = []
    for q in questions:
        q_data.append({
            "question_id": q.id,
            "question_text": q.content,
            "upvote_count": q.upvote_count(),
            "moderation_status": q.moderation_status,
            "is_answered": q.is_answered,
            "created_at": q.created_at.isoformat()
        })

    if len(q_data) < 2:
        raise ValueError("Not enough questions to generate groups.")

    prompt_content = f"""
    You are an AI assistant helping moderate a live event Q&A session.
    Below are questions submitted by attendees, in JSON format:
    {json.dumps(q_data, indent=2)}

    Your task is to identify groups of questions that are asking about the same topic,
    and for each group produce a single synthesized representative question that captures
    the intent of ALL questions in that group.

    Rules:
    - A group must contain at least 2 questions.
    - Create a maximum of 10 groups.
    - Do not force unrelated questions into a group just to reach the maximum.
    - The "summary" field MUST be a complete, well-formed question (ending with "?") that
      synthesizes and represents all sub-questions in the group. It should read naturally
      as a standalone question a moderator could ask the speaker. Do NOT write a sentence
      like "Questions about X and Y." — write an actual question.
    - The "title" field must be a short 2–5 word category label (e.g. "Pricing & Access").
    - The "confidence" field is a float between 0 and 1 representing how confident you are
      that these questions belong together.

    Example of correct output for a group about ticket pricing:
    {{
      "title": "Ticket Pricing",
      "summary": "What are the ticket pricing tiers, are there any early-bird or group discounts, and is there a free access option for students or community members?",
      "question_ids": [12, 18, 21],
      "confidence": 0.88
    }}

    Output MUST be strictly valid JSON in this exact structure:
    {{
      "groups": [
        {{
          "title": "Short Category Label",
          "summary": "A complete synthesized question that represents all sub-questions in this group?",
          "question_ids": [1, 2, 3],
          "confidence": 0.85
        }}
      ]
    }}
    """
    
    api_key = getattr(settings, "OPENAI_API_KEY", "") or os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        logger.error("[AI-GROUPING] OpenAI API key not configured")
        raise ValueError("OpenAI API key not configured on server.")

    logger.info(f"[AI-GROUPING] API key found: {api_key[:10]}...")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    data = {
        "model": "gpt-3.5-turbo",
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": "You are a helpful Q&A moderator grouping bot designed to output JSON."},
            {"role": "user", "content": prompt_content}
        ],
        "temperature": 0.2
    }

    logger.info(f"[AI-GROUPING] Calling OpenAI API with {len(q_data)} questions")

    try:
        response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=data, timeout=30)
    except Exception as e:
        logger.error(f"[AI-GROUPING] API connection failed: {str(e)}")
        raise ValueError(f"Failed to connect to AI service: {str(e)}")

    logger.info(f"[AI-GROUPING] OpenAI API response status: {response.status_code}")

    if response.status_code != 200:
        logger.error(f"[AI-GROUPING] API error: {response.text}")
        raise ValueError(f"AI service error: {response.text}")

    result_text = response.json().get("choices", [{}])[0].get("message", {}).get("content", "")
    if not result_text:
        raise ValueError("Empty response from AI service.")

    try:
        parsed = json.loads(result_text)
        groups = parsed.get("groups", [])
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse JSON from AI response: {str(e)}")
        
    valid_ids = set(q["question_id"] for q in q_data)
    
    logger.info(f"[AI-GROUPING] AI returned {len(groups)} groups")

    created_suggestions = []

    for g in groups:
        suggested_ids = g.get("question_ids", [])
        if not isinstance(suggested_ids, list):
            logger.info(f"[AI-GROUPING] Skipping group: question_ids not a list")
            continue

        valid_suggested_ids = [qid for qid in suggested_ids if qid in valid_ids]

        # Eliminate duplicates
        valid_suggested_ids = list(dict.fromkeys(valid_suggested_ids))

        if len(valid_suggested_ids) < 2:
            logger.info(f"[AI-GROUPING] Skipping group: only {len(valid_suggested_ids)} valid questions")
            continue # skip invalid group

        logger.info(f"[AI-GROUPING] Creating suggestion with title='{g.get('title')}', qids={valid_suggested_ids}")

        suggestion = QnAQuestionGroupSuggestion.objects.create(
            event_id=event_id,
            generated_by=user,
            status="pending",
            raw_ai_response=result_text,
            suggested_title=str(g.get("title", "Untitled Group"))[:255],
            suggested_summary=str(g.get("summary", "")),
            confidence_score=float(g.get("confidence", 0.0)),
            suggested_question_ids=valid_suggested_ids
        )
        created_suggestions.append(suggestion)

    if not created_suggestions:
        logger.error("[AI-GROUPING] No valid groups created from AI response")
        raise ValueError("AI returned no valid valid groups with at least 2 questions.")

    logger.info(f"[AI-GROUPING] ✅ Created {len(created_suggestions)} suggestions")
    return created_suggestions
