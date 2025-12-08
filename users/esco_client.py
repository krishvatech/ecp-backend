# users/esco_client.py
import requests

ESCO_BASE_URL = "https://ec.europa.eu/esco/api"

def search_skills(query: str, language: str = "en", limit: int = 10) -> list[dict]:
    params = {
        "text": query,
        "type": "skill",
        "language": language,
        "limit": limit,
    }
    url = f"{ESCO_BASE_URL}/search"
    resp = requests.get(url, params=params, timeout=5)
    if resp.status_code != 200:
        return []
    data = resp.json()
    # Shape depends on ESCO API; we just pass through for now
    return data.get("_embedded", {}).get("results", [])
