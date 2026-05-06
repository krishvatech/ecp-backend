import requests
from django.conf import settings
import logging
import base64

logger = logging.getLogger(__name__)


def reactivate_staff_user(email, auth_token=None):
    """Find a deactivated staff user and reactivate them."""
    saleor_url = getattr(settings, "SALEOR_API_URL", None)

    if not saleor_url or not auth_token:
        return None

    # First, find the staff user by email
    query = """
    query($email: String!) {
        staffUsers(first: 1, filter: {search: $email}) {
            edges {
                node {
                    id
                    email
                }
            }
        }
    }
    """

    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(
            saleor_url,
            json={"query": query, "variables": {"email": email}},
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        data = response.json()

        if "errors" in data:
            logger.debug(f"Error finding staff user {email}: {data['errors']}")
            return None

        edges = data.get("data", {}).get("staffUsers", {}).get("edges", [])
        if not edges:
            logger.warning(f"Staff user {email} not found")
            return None

        staff_id = edges[0]["node"]["id"]
        logger.info(f"Found deactivated staff user {email}, reactivating...")

        # Now reactivate them
        mutation = """
        mutation($id: ID!) {
            staffUpdate(id: $id, input: {isActive: true}) {
                user {
                    id
                    email
                }
                errors {
                    field
                    message
                }
            }
        }
        """

        response = requests.post(
            saleor_url,
            json={"query": mutation, "variables": {"id": staff_id}},
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        data = response.json()

        if "errors" in data:
            logger.error(f"Saleor error reactivating user: {data['errors']}")
            return None

        result = data.get("data", {}).get("staffUpdate", {})
        if result.get("errors"):
            logger.error(f"Failed to reactivate staff user: {result['errors']}")
            return None

        logger.info(f"Successfully reactivated {email}")
        return staff_id

    except Exception as e:
        logger.error(f"Failed to reactivate staff user: {e}")
        return None


def get_existing_user_id(email, auth_token=None):
    """Try to retrieve an existing user's ID by querying staff users.
    Falls back to app token if user token fails."""
    saleor_url = getattr(settings, "SALEOR_API_URL", None)

    if not saleor_url:
        return None

    # Try querying staff users by email (since we're creating staff users)
    query = """
    query($email: String!) {
        staffUsers(first: 1, filter: {search: $email}) {
            edges {
                node {
                    id
                }
            }
        }
    }
    """

    # Try with user token first, then fall back to app token
    tokens_to_try = []
    if auth_token:
        tokens_to_try.append(auth_token)

    app_token = getattr(settings, "SALEOR_APP_TOKEN", None)
    if app_token:
        tokens_to_try.append(app_token)

    for token in tokens_to_try:
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        try:
            response = requests.post(
                saleor_url,
                json={"query": query, "variables": {"email": email}},
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            if "errors" in data:
                logger.debug(f"Error querying for user {email} with this token: {data['errors']}")
                continue

            edges = data.get("data", {}).get("users", {}).get("edges", [])
            if edges:
                logger.info(f"Found existing user {email} with ID {edges[0]['node']['id']}")
                return edges[0]["node"]["id"]
        except Exception as e:
            logger.debug(f"Failed to get existing user ID for {email}: {e}")
            continue

    return None


# ============= STAFF SYNC (Platform Admin) =============

def get_saleor_user_token(email, password):
    """
    Get a Saleor user token using email and password.
    This authenticates as the staff user and returns a token.
    """
    saleor_url = getattr(settings, "SALEOR_API_URL", None)
    if not saleor_url:
        return None

    mutation = """
    mutation($email: String!, $password: String!) {
        tokenCreate(email: $email, password: $password) {
            token
            user {
                id
                email
            }
            errors {
                field
                message
            }
        }
    }
    """

    variables = {
        "email": email,
        "password": password
    }

    try:
        response = requests.post(
            saleor_url,
            json={"query": mutation, "variables": variables},
            timeout=10
        )
        response.raise_for_status()
        data = response.json()

        if "errors" in data:
            logger.error(f"Saleor tokenCreate error: {data['errors']}")
            return None

        result = data.get("data", {}).get("tokenCreate", {})
        if result.get("errors"):
            logger.error(f"Failed to get user token: {result['errors']}")
            return None

        token = result.get("token")
        if token:
            logger.info(f"Successfully got user token for {email}")
            return token
        return None
    except Exception as e:
        logger.error(f"Failed to get Saleor user token: {e}")
        return None


def get_full_access_group_id(auth_token=None):
    """Get the 'Full Access' permission group ID from Saleor"""
    saleor_url = getattr(settings, "SALEOR_API_URL", None)

    if not saleor_url:
        logger.warning("Saleor not configured: missing SALEOR_API_URL")
        return None

    if not auth_token:
        logger.warning("No auth token provided to get Full Access group")
        return None

    query = """
    query {
        permissionGroups(first: 100) {
            edges {
                node {
                    id
                    name
                }
            }
        }
    }
    """

    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(
            saleor_url,
            json={"query": query},
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        data = response.json()

        if "errors" in data:
            logger.error(f"Saleor error getting groups: {data['errors']}")
            return None

        # Find "Full Access" group
        for edge in data.get("data", {}).get("permissionGroups", {}).get("edges", []):
            if edge["node"]["name"] == "Full Access":
                return edge["node"]["id"]

        logger.warning("'Full Access' permission group not found in Saleor")
        return None
    except Exception as e:
        logger.error(f"Failed to get Full Access group: {e}")
        return None


def get_saleor_staff_by_email(email, auth_token=None):
    """Check if user exists as staff in Saleor"""
    saleor_url = getattr(settings, "SALEOR_API_URL", None)

    if not saleor_url or not auth_token:
        return None

    query = """
    query($email: String!) {
        staffUsers(first: 1, filter: {search: $email}) {
            edges {
                node {
                    id
                    email
                    isActive
                }
            }
        }
    }
    """

    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(
            saleor_url,
            json={"query": query, "variables": {"email": email}},
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        data = response.json()

        if "errors" in data:
            logger.error(f"Saleor error checking {email}: {data['errors']}")
            return None

        edges = data.get("data", {}).get("staffUsers", {}).get("edges", [])
        logger.debug(f"Saleor staffUsers response for {email}: {len(edges)} results")
        if edges:
            node = edges[0]["node"]
            staff_id = node["id"]
            is_active = node.get("isActive", False)
            if not is_active:
                logger.debug(f"Staff user {email} found but is inactive")
                return None
            logger.info(f"Found active staff user {email} in Saleor: {staff_id}")
            return staff_id

        logger.debug(f"User {email} not found in Saleor staff")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to check Saleor staff user: {e}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                logger.error(f"Saleor response body: {e.response.text}")
            except:
                pass
        return None
    except Exception as e:
        logger.error(f"Failed to check Saleor staff user: {e}")
        return None


def create_saleor_staff_user(email, first_name="", last_name="", auth_token=None):
    """Create a staff user in Saleor using user token.
    If user already exists (inactive), reactivate them."""
    saleor_url = getattr(settings, "SALEOR_API_URL", None)

    if not saleor_url or not auth_token:
        return None

    mutation = """
    mutation($input: StaffCreateInput!) {
        staffCreate(input: $input) {
            user {
                id
                email
            }
            errors {
                field
                message
            }
        }
    }
    """

    variables = {
        "input": {
            "email": email,
            "firstName": first_name or "",
            "lastName": last_name or "",
            "isActive": True,
        }
    }

    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(
            saleor_url,
            json={"query": mutation, "variables": variables},
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        data = response.json()

        if "errors" in data:
            logger.error(f"Saleor error: {data['errors']}")
            return None

        result = data.get("data", {}).get("staffCreate", {})
        if result.get("errors"):
            errors = result['errors']
            # Check if user already exists
            already_exists = any("already exists" in str(e.get("message", "")).lower() for e in errors)
            if already_exists:
                logger.info(f"User {email} already exists in Saleor. Attempting to reactivate.")
                # Find the user and reactivate them
                return reactivate_staff_user(email, auth_token)
            else:
                logger.error(f"Failed to create staff user: {errors}")
                return None

        return result.get("user", {}).get("id")
    except Exception as e:
        logger.error(f"Failed to create Saleor staff user: {e}")
        return None


def assign_user_to_group(staff_id, group_id, auth_token=None):
    """Assign staff user to a permission group using user token"""
    saleor_url = getattr(settings, "SALEOR_API_URL", None)

    if not saleor_url or not auth_token:
        return False

    mutation = """
    mutation($id: ID!, $groupIds: [ID!]!) {
        staffUpdate(id: $id, input: {addGroups: $groupIds}) {
            user {
                id
                email
            }
            errors {
                field
                message
            }
        }
    }
    """

    variables = {
        "id": staff_id,
        "groupIds": [group_id]
    }

    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }

    try:
        logger.debug(f"Assigning staff_id={staff_id} to group_id={group_id}")
        response = requests.post(
            saleor_url,
            json={"query": mutation, "variables": variables},
            headers=headers,
            timeout=10
        )
        logger.debug(f"Response status: {response.status_code}")
        response.raise_for_status()
        data = response.json()

        if "errors" in data:
            logger.error(f"Saleor GraphQL error: {data['errors']}")
            return False

        result = data.get("data", {}).get("staffUpdate", {})
        if result.get("errors"):
            logger.error(f"Failed to assign group: {result['errors']}")
            return False

        logger.info(f"Successfully assigned user {staff_id} to group {group_id}")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed for staffUpdate: {e}")
        if hasattr(e.response, 'text'):
            logger.error(f"Response body: {e.response.text}")
        return False
    except Exception as e:
        logger.error(f"Failed to assign user to group: {e}")
        return False


def remove_platform_admin_from_saleor(user_email, auth_token=None):
    """
    Remove a platform_admin user from Saleor by deactivating their staff account.

    Args:
        user_email: User's email

    Returns:
        dict: {"success": bool, "message": str}
    """
    logger.info(f"Attempting to remove {user_email} from Saleor...")

    if not auth_token:
        logger.warning("No Saleor auth token provided. Skipping removal.")
        return {
            "success": False,
            "message": "Saleor SSO connection with MANAGE_STAFF is required"
        }

    # Find the user by email
    saleor_url = getattr(settings, "SALEOR_API_URL", None)
    if not saleor_url:
        return {"success": False, "message": "SALEOR_API_URL not configured"}

    query = """
    query($email: String!) {
        staffUsers(first: 1, filter: {search: $email}) {
            edges {
                node {
                    id
                    email
                }
            }
        }
    }
    """

    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(
            saleor_url,
            json={"query": query, "variables": {"email": user_email}},
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        data = response.json()

        if "errors" in data:
            logger.warning(f"Saleor error finding user: {data['errors']}")
            return {
                "success": False,
                "message": "User not found in Saleor"
            }

        edges = data.get("data", {}).get("staffUsers", {}).get("edges", [])
        if not edges:
            logger.info(f"User {user_email} not found in Saleor (already removed or never synced)")
            return {
                "success": True,
                "message": "User not found in Saleor (already removed)"
            }

        staff_id = edges[0]["node"]["id"]
        logger.info(f"Found staff user {user_email} in Saleor: {staff_id}")

        # Delete the staff user from Saleor
        mutation = """
        mutation($id: ID!) {
            staffDelete(id: $id) {
                user {
                    id
                    email
                }
                errors {
                    field
                    message
                }
            }
        }
        """

        response = requests.post(
            saleor_url,
            json={"query": mutation, "variables": {"id": staff_id}},
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        data = response.json()

        if "errors" in data:
            logger.error(f"Saleor error deleting user: {data['errors']}")
            return {
                "success": False,
                "message": "Failed to delete staff user"
            }

        result = data.get("data", {}).get("staffDelete", {})
        if result.get("errors"):
            logger.error(f"Failed to delete staff user: {result['errors']}")
            return {
                "success": False,
                "message": "Failed to delete staff user"
            }

        logger.info(f"Successfully deleted {user_email} from Saleor")
        return {
            "success": True,
            "message": f"Successfully removed {user_email} from Saleor"
        }

    except Exception as e:
        logger.error(f"Failed to remove user from Saleor: {e}")
        return {
            "success": False,
            "message": f"Error: {str(e)}"
        }


def sync_platform_admin_to_saleor(user_email, first_name="", last_name="", is_platform_admin=False, auth_token=None):
    """
    Sync platform_admin user to Saleor as staff with Full Access.
    Uses the connected Saleor staff user's token to create staff via staffCreate mutation.

    Args:
        user_email: User's email
        first_name: User's first name
        last_name: User's last name
        is_platform_admin: Whether user should have Full Access

    Returns:
        dict: {"success": bool, "staff_id": str or None, "message": str}
    """
    if not is_platform_admin:
        return {"success": True, "staff_id": None, "message": "User is not platform_admin"}

    logger.info(f"Attempting to sync {user_email} to Saleor...")

    if not auth_token:
        logger.warning("No Saleor auth token provided. Skipping sync.")
        return {
            "success": False,
            "staff_id": None,
            "message": "Saleor SSO connection with MANAGE_STAFF is required"
        }

    # Try to create staff user with connected Saleor user token
    # (Skip the check since staff users may not have query permissions for staffMembers)
    staff_id = create_saleor_staff_user(user_email, first_name, last_name, auth_token=auth_token)
    if not staff_id:
        return {
            "success": False,
            "staff_id": None,
            "message": "Failed to create staff user in Saleor"
        }

    logger.info(f"Created staff user {user_email} in Saleor: {staff_id}")

    # Get Full Access group ID
    group_id = get_full_access_group_id(auth_token=auth_token)
    if not group_id:
        return {
            "success": False,
            "staff_id": staff_id,
            "message": "Failed to find 'Full Access' group in Saleor"
        }

    # Assign to Full Access group
    if assign_user_to_group(staff_id, group_id, auth_token=auth_token):
        return {
            "success": True,
            "staff_id": staff_id,
            "message": f"Successfully synced {user_email} to Saleor with Full Access"
        }
    else:
        return {
            "success": False,
            "staff_id": staff_id,
            "message": "Failed to assign Full Access permission group"
        }

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
