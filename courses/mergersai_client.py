"""
Mergers.AI REST API client for backend-proxied calls.

This module handles all communication with the Mergers.AI API.
The backend acts as a proxy to avoid exposing the X-Embed-Api-Key in frontend code.

All API calls require:
  - Header: X-Embed-Api-Key (from settings.MERGERSAI_EMBED_API_KEY)
  - Base URL: settings.MERGERSAI_API_BASE_URL (default: https://api.mergers.ai)

Endpoints:
  - GET /api/v1/embed/status
  - GET /api/v1/embed/my-courses?user_email=<email>
  - POST /api/v1/embed/video-search
"""
import logging
from typing import Optional, Dict, Any

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

# Default timeout for all Mergers.AI API calls
MERGERSAI_TIMEOUT = 15


def _check_api_key_configured() -> str:
    """
    Verify that the Mergers.AI embed API key is configured.

    Raises:
        ValueError: If MERGERSAI_EMBED_API_KEY is not configured
    """
    api_key = settings.MERGERSAI_EMBED_API_KEY
    if not api_key:
        raise ValueError(
            "Mergers.AI embed API key is not configured. "
            "Set MERGERSAI_EMBED_API_KEY in .env or Django settings before using Mergers.AI API."
        )
    return api_key


def _build_headers() -> Dict[str, str]:
    """Build HTTP headers for Mergers.AI API calls."""
    api_key = _check_api_key_configured()
    return {
        "X-Embed-Api-Key": api_key,
        "Content-Type": "application/json",
    }


def mergersai_status() -> Dict[str, Any]:
    """
    Check Mergers.AI integration health.

    Calls: GET {MERGERSAI_API_BASE_URL}/api/v1/embed/status

    Returns:
        Response JSON from Mergers.AI status endpoint

    Raises:
        requests.RequestException: On network or API errors
        ValueError: If MERGERSAI_EMBED_API_KEY is not configured
    """
    api_base = settings.MERGERSAI_API_BASE_URL
    url = f"{api_base}/api/v1/embed/status"
    headers = _build_headers()

    logger.debug("Calling Mergers.AI status endpoint: %s", url)

    try:
        resp = requests.get(
            url,
            headers=headers,
            timeout=MERGERSAI_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        logger.debug("Mergers.AI status check successful: %s", data)
        return data
    except requests.Timeout as e:
        logger.warning("Mergers.AI status check timeout after %ds: %s", MERGERSAI_TIMEOUT, e)
        raise
    except requests.RequestException as e:
        logger.error("Mergers.AI status check failed: %s", e)
        raise


def mergersai_my_courses(user_email: str) -> Dict[str, Any]:
    """
    Get list of courses available to the user in Mergers.AI.

    Calls: GET {MERGERSAI_API_BASE_URL}/api/v1/embed/my-courses?user_email=<email>

    Args:
        user_email: User's email address (from request.user.email, not frontend)

    Returns:
        Response JSON from Mergers.AI, typically:
        {
            "courses": [
                {
                    "id": "course-slug",
                    "slug": "course-slug",
                    "name": "Course Name",
                    "has_vector_content": true
                },
                ...
            ]
        }

    Raises:
        requests.RequestException: On network or API errors
        ValueError: If MERGERSAI_EMBED_API_KEY is not configured
    """
    api_base = settings.MERGERSAI_API_BASE_URL
    url = f"{api_base}/api/v1/embed/my-courses"
    headers = _build_headers()
    params = {"user_email": user_email}

    logger.info(
        "=== MERGERSAI MY-COURSES REQUEST ===\n"
        "URL: %s\n"
        "Query Params: user_email=%s\n"
        "Headers: X-Embed-Api-Key: [REDACTED]",
        url,
        user_email,
    )

    try:
        resp = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=MERGERSAI_TIMEOUT,
        )

        logger.info(
            "=== MERGERSAI MY-COURSES RESPONSE ===\n"
            "Status Code: %d\n"
            "Response Headers: %s\n"
            "Response Body (FULL): %s",
            resp.status_code,
            dict(resp.headers),
            resp.text,  # FULL response
        )

        resp.raise_for_status()
        data = resp.json()
        logger.debug("Mergers.AI my-courses successful for user=%s: %d courses", user_email, len(data.get("courses", [])))
        return data
    except requests.Timeout as e:
        logger.warning("Mergers.AI my-courses timeout for user=%s after %ds: %s", user_email, MERGERSAI_TIMEOUT, e)
        raise
    except requests.RequestException as e:
        logger.error("Mergers.AI my-courses failed for user=%s: %s", user_email, e)
        raise


def mergersai_video_search(
    user_email: str,
    course_slug: str,
    question: str,
    top_k: int = 3,
) -> Dict[str, Any]:
    """
    Search for videos relevant to a question within a course.

    Calls: POST {MERGERSAI_API_BASE_URL}/api/v1/embed/video-search

    Args:
        user_email: User's email address (from request.user.email, not frontend)
        course_slug: Course identifier (e.g., "cpmi-virtual-live-march-2024")
        question: User's search question (must be non-empty)
        top_k: Maximum number of results to return (default 3, max ~10)

    Returns:
        Response JSON from Mergers.AI, typically:
        {
            "results": [
                {
                    "title": "Segment Title",
                    "course_name": "Course Name",
                    "confidence_score": 0.92,
                    "transcript_segment": "Relevant text excerpt...",
                    "vimeo_embed_url": "https://player.vimeo.com/...",
                    "start_time": 120,
                    "end_time": 180,
                },
                ...
            ]
        }

    Raises:
        requests.RequestException: On network or API errors
        ValueError: If MERGERSAI_EMBED_API_KEY is not configured
    """
    api_base = settings.MERGERSAI_API_BASE_URL
    url = f"{api_base}/api/v1/embed/video-search"
    headers = _build_headers()

    payload = {
        "user_email": user_email,
        "course_slug": course_slug,
        "question": question,
        "top_k": top_k,
    }

    logger.info(
        "=== MERGERSAI VIDEO SEARCH REQUEST ===\n"
        "URL: %s\n"
        "Headers: X-Embed-Api-Key: [REDACTED]\n"
        "Payload: user_email=%s, course_slug=%s, question=%s, top_k=%d",
        url,
        user_email,
        course_slug,
        question[:100],
        top_k,
    )

    try:
        resp = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=MERGERSAI_TIMEOUT,
        )

        logger.info(
            "=== MERGERSAI VIDEO SEARCH RESPONSE ===\n"
            "Status Code: %d\n"
            "Response Headers: %s\n"
            "Response Body (FULL): %s",
            resp.status_code,
            dict(resp.headers),
            resp.text,  # FULL response
        )

        resp.raise_for_status()
        data = resp.json()
        results = data.get("results", [])
        logger.debug(
            "Mergers.AI video-search successful for user=%s course=%s: %d results",
            user_email,
            course_slug,
            len(results),
        )
        return data
    except requests.Timeout as e:
        logger.warning(
            "Mergers.AI video-search timeout for user=%s course=%s after %ds: %s",
            user_email,
            course_slug,
            MERGERSAI_TIMEOUT,
            e,
        )
        raise
    except requests.RequestException as e:
        logger.error("Mergers.AI video-search failed for user=%s course=%s: %s", user_email, course_slug, e)
        raise
