# users/esco_client.py
import logging
import requests

logger = logging.getLogger(__name__)

ESCO_BASE_URL = "https://ec.europa.eu/esco/api"


def search_skills(query: str, language: str = "en", limit: int = 10) -> list[dict]:
    params = {
        "text": query,
        "type": "skill",
        "language": language,
        "limit": limit,
    }
    url = f"{ESCO_BASE_URL}/search"

    logger.info(
        "[ESCO] Calling ESCO /search with query=%r language=%s limit=%s",
        query, language, limit,
    )
    resp = requests.get(url, params=params, timeout=5)

    logger.info(
        "[ESCO] ESCO /search URL=%s status=%s",
        resp.url, resp.status_code,
    )

    if resp.status_code != 200:
        logger.warning(
            "[ESCO] Non-200 response from ESCO. status=%s body_snippet=%r",
            resp.status_code,
            resp.text[:300],
        )
        return []

    data = resp.json()
    results = data.get("_embedded", {}).get("results", []) or []

    # Log only first item to avoid huge logs
    first = results[0] if results else None
    logger.info(
        "[ESCO] Parsed %d skills from ESCO. First=%r",
        len(results), first,
    )
    return results

