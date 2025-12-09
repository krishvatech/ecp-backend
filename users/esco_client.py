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
    url = f"{ESCO_BASE_URL}/suggest2"

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

def fetch_skill_details(uri: str) -> dict:
    """
    Fetches detailed information (description, alt labels, type) for a specific ESCO skill URI.
    """
    endpoint = "https://ec.europa.eu/esco/api/resource/skill"
    params = {
        "uri": uri,
        "language": "en",
        "selectedVersion": "latest"
    }

    logger.info("[ESCO] Fetching details for URI=%s", uri)

    try:
        response = requests.get(endpoint, params=params, timeout=10)
        
        if response.status_code != 200:
            logger.warning("[ESCO] Failed to fetch details. Status=%s", response.status_code)
            return None

        data = response.json()

        # 1. Extract Description
        desc_map = data.get('description', {})
        desc_obj = desc_map.get('en') or desc_map.get('en-us') or {}
        description = desc_obj.get('literal', '')

        # 2. Extract Alternative Labels
        alt_labels_map = data.get('alternativeLabel', {})
        alternative_labels = alt_labels_map.get('en', [])

        # 3. Extract Skill Type (FIX: Look inside _links)
        links = data.get('_links', {})
        skill_type_data = links.get('hasSkillType', [])
        
        # We take the title of the first type found (e.g., "skill" or "knowledge")
        skill_type = skill_type_data[0].get('title', '') if skill_type_data else ''

        return {
            "description": description,
            "alternative_labels": alternative_labels,
            "skill_type": skill_type
        }

    except Exception as e:
        logger.error("[ESCO] Exception fetching details for %s: %s", uri, str(e))
        return None