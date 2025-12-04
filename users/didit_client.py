import hashlib
import hmac
import json
import requests
from django.conf import settings
from django.urls import reverse

# Didit API Constants
DIDIT_BASE_URL = "https://verification.didit.me/v2"

def _get_headers():
    return {
        "Content-Type": "application/json",
        "x-api-key": settings.DIDIT_API_KEY,
    }

def create_session(user_id: str, workflow_id: str, vendor_data: str, callback_url: str = None) -> tuple[str, str]:
    """
    Generic function to create a Didit verification session.
    Returns (session_id, url).
    """
    if not workflow_id:
        raise ValueError("Didit Workflow ID is not configured.")

    payload = {
        "workflow_id": workflow_id,
        "vendor_data": vendor_data,
        "metadata": {
            "user_id": str(user_id)
        }
    }
    
    # Optional: explicitly set callback if provided, otherwise Didit uses the Console setting
    if callback_url:
        payload["callback"] = callback_url

    try:
        response = requests.post(
            f"{DIDIT_BASE_URL}/session/",
            headers=_get_headers(),
            json=payload,
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        return data.get("session_id"), data.get("url")
    except requests.RequestException as e:
        print(f"Didit API Error: {e}")
        if e.response:
            print(f"Response: {e.response.text}")
        raise e

def create_initial_kyc_session(user, request=None) -> tuple[str, str]:
    """
    Creates a Didit session for first-time KYC.
    Vendor data format: "kyc_initial:<user_id>"
    """
    # Construct absolute callback URL if request is available
    callback_url = None
    if request:
        # Assumes you have a named URL 'didit-webhook'
        try:
            path = reverse("didit-webhook")
            callback_url = request.build_absolute_uri(path)
        except Exception:
            pass

    vendor_data = f"kyc_initial:{user.id}"
    return create_session(
        user_id=str(user.id),
        workflow_id=settings.DIDIT_WORKFLOW_ID_KYC,
        vendor_data=vendor_data,
        callback_url=callback_url
    )

def create_name_change_kyc_session(name_change_request, request=None) -> tuple[str, str]:
    """
    Creates a Didit session for a NameChangeRequest.
    Vendor data format: "kyc_namechange:<request_id>"
    """
    # Construct absolute callback URL
    callback_url = None
    if request:
        try:
            path = reverse("didit-webhook")
            callback_url = request.build_absolute_uri(path)
        except Exception:
            pass

    vendor_data = f"kyc_namechange:{name_change_request.id}"
    # Use specific workflow ID if set, otherwise fallback to standard KYC workflow
    workflow_id = settings.DIDIT_WORKFLOW_ID_NAME_CHANGE or settings.DIDIT_WORKFLOW_ID_KYC
    
    return create_session(
        user_id=str(name_change_request.user.id),
        workflow_id=workflow_id,
        vendor_data=vendor_data,
        callback_url=callback_url
    )

def verify_webhook_signature(request) -> bool:
    """
    Verifies the `x-signature` header using the DIDIT_WEBHOOK_SECRET.
    Didit usually uses HMAC-SHA256 on the raw request body.
    """
    secret = settings.DIDIT_WEBHOOK_SECRET
    if not secret:
        return False

    signature = request.headers.get("x-signature")
    if not signature:
        return False

    # Calculate expected signature
    # Ensure body is read as bytes
    body = request.body 
    expected_signature = hmac.new(
        key=secret.encode('utf-8'),
        msg=body,
        digestmod=hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, expected_signature)

def get_session_details(session_id: str) -> dict:
    """
    Fetches full session details/decision from Didit API.
    Useful if the webhook payload is incomplete.
    """
    url = f"{DIDIT_BASE_URL}/session/{session_id}/decision/"
    response = requests.get(url, headers=_get_headers(), timeout=10)
    if response.status_code == 200:
        return response.json()
    return {}