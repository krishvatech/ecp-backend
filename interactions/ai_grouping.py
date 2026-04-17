import json
import requests
import os
from django.conf import settings
from .models import Question, QnAQuestionGroupSuggestion

def suggest_groups(event_id, user):
    """
    Fetches questions for an event and uses an AI service to suggest groups.
    """
    questions = Question.objects.filter(event_id=event_id, is_hidden=False)
    
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
    You are an AI assistant designed to group related Q&A questions for an event.
    Here are the current questions in JSON format:
    {json.dumps(q_data, indent=2)}
    
    Group related questions together.
    Rules:
    - A group must have at least 2 questions.
    - Create a maximum of 10 groups.
    - Do not group unrelated questions just to hit the max.
    - Output MUST be strictly valid JSON in this exact structure:
    {{
      "groups": [
        {{
          "title": "Pricing and Access",
          "summary": "Questions about ticket pricing, access rules, and joining options.",
          "question_ids": [12, 18, 21],
          "confidence": 0.86
        }}
      ]
    }}
    """
    
    api_key = getattr(settings, "OPENAI_API_KEY", "") or os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        raise ValueError("OpenAI API key not configured on server.")

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
    
    try:
        response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=data, timeout=30)
    except Exception as e:
        raise ValueError(f"Failed to connect to AI service: {str(e)}")

    if response.status_code != 200:
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
    
    created_suggestions = []
    
    for g in groups:
        suggested_ids = g.get("question_ids", [])
        if not isinstance(suggested_ids, list):
            continue
            
        valid_suggested_ids = [qid for qid in suggested_ids if qid in valid_ids]
        
        # Eliminate duplicates
        valid_suggested_ids = list(dict.fromkeys(valid_suggested_ids))
        
        if len(valid_suggested_ids) < 2:
            continue # skip invalid group
            
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
        raise ValueError("AI returned no valid valid groups with at least 2 questions.")

    return created_suggestions
