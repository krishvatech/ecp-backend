import requests
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def sync_user_to_saleor_sync(user):
    """
    Synchronously checks if user exists in Saleor, creates if not,
    and updates user.profile.saleor_customer_id.
    """
    if not user.email:
        return

    # If we already have an ID, assume synced (or add logic to verify if needed)
    if hasattr(user, 'profile') and user.profile.saleor_customer_id:
        return

    saleor_url = getattr(settings, "SALEOR_API_URL", None)
    saleor_token = getattr(settings, "SALEOR_APP_TOKEN", None)

    if not saleor_url or not saleor_token:
        logger.warning("Skipping Saleor sync: SALEOR_API_URL or SALEOR_APP_TOKEN not set.")
        return

    headers = {
        "Authorization": f"Bearer {saleor_token}",
        "Content-Type": "application/json"
    }

    # 1. Check existing
    check_query = """
    query CheckCustomer($email: String!) {
      customers(filter: {search: $email}, first: 1) {
        edges { node { id email } }
      }
      staffUsers(filter: {search: $email}, first: 1) {
         edges { node { id email } }
      }
    }
    """
    
    found_id = None
    
    try:
        r = requests.post(saleor_url, json={"query": check_query, "variables": {"email": user.email}}, headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json()
            # Remove debug print
            
            cust_edges = data.get("data", {}).get("customers", {}).get("edges", [])
            staff_edges = data.get("data", {}).get("staffUsers", {}).get("edges", [])
            
            for edge in cust_edges:
                if edge["node"]["email"].lower() == user.email.lower():
                     found_id = edge["node"]["id"]
                     break
            if not found_id:
                for edge in staff_edges:
                    if edge["node"]["email"].lower() == user.email.lower():
                        found_id = edge["node"]["id"]
                        break
    except Exception as e:
        logger.error(f"Saleor sync check error: {e}")
        return

    # 2. If found, save and return
    if found_id:
        if hasattr(user, 'profile'):
            user.profile.saleor_customer_id = found_id
            user.profile.save(update_fields=["saleor_customer_id"])
        return

    # 3. Create if not found
    mutation = """
    mutation CreateCustomer($input: UserCreateInput!) {
      customerCreate(input: $input) {
        user { id email }
        errors { field message }
      }
    }
    """
    first_name = user.first_name or user.username
    last_name = user.last_name or ""
    
    try:
        if hasattr(user, 'profile') and user.profile.full_name:
            parts = user.profile.full_name.split(" ", 1)
            first_name = parts[0]
            if len(parts) > 1:
                last_name = parts[1]
    except:
        pass

    variables = {
        "input": {
            "email": user.email,
            "firstName": first_name,
            "lastName": last_name,
            "isActive": True,
        }
    }
    
    try:
        r = requests.post(saleor_url, json={"query": mutation, "variables": variables}, headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json()
            errors = data.get("data", {}).get("customerCreate", {}).get("errors", [])
            
            if not errors:
                new_user = data.get("data", {}).get("customerCreate", {}).get("user", {})
                new_id = new_user.get("id")
                if new_id and hasattr(user, 'profile'):
                    user.profile.saleor_customer_id = new_id
                    user.profile.save(update_fields=["saleor_customer_id"])
            else:
                 # Check for "already exists" error
                 already_exists = any("already exists" in str(e.get("message", "")) for e in errors)
                 if already_exists:
                     logger.warning(f"User {user.email} already exists in Saleor but was not found in search. Attempting fallback.")
                     # Fallback: Mark as synced_unknown to stop loop, OR try valid brute force? 
                     # For now, mark as error so we stop hitting API
                     if hasattr(user, 'profile'):
                         # Use placeholder to stop loop. You can manually fix via admin later.
                         user.profile.saleor_customer_id = "synced_existing_unknown_id"
                         user.profile.save(update_fields=["saleor_customer_id"])
                 else:
                     logger.error(f"Saleor create errors: {errors}")
    except Exception as e:
        logger.error(f"Saleor create error: {e}")
