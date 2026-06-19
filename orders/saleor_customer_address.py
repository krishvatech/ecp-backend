import requests
import logging
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)


def delete_billing_address_from_saleor(user, billing_address):
    """
    Delete a billing address from Saleor customer account.

    Args:
        user: Django user instance
        billing_address: BillingAddress model instance

    Returns:
        dict: {
            "success": bool,
            "deleted_from_saleor": bool,
            "error": str or None
        }
    """
    saleor_url = getattr(settings, "SALEOR_API_URL", None)
    saleor_token = getattr(settings, "SALEOR_APP_TOKEN", None)

    result = {
        "success": True,
        "deleted_from_saleor": False,
        "error": None,
    }

    # Saleor not configured - just return success
    if not saleor_url or not saleor_token:
        logger.debug("Saleor not configured. Skipping address deletion from Saleor.")
        return result

    # No saleor_address_id to delete
    if not billing_address.saleor_address_id:
        logger.debug(f"No Saleor address ID for billing address {billing_address.id}")
        return result

    saleor_address_id = billing_address.saleor_address_id

    headers = {
        "Authorization": f"Bearer {saleor_token}",
        "Content-Type": "application/json",
    }

    try:
        mutation = """
        mutation DeleteAddress($id: ID!) {
          addressDelete(id: $id) {
            errors {
              field
              message
            }
          }
        }
        """
        variables = {"id": saleor_address_id}

        response = requests.post(
            saleor_url,
            json={"query": mutation, "variables": variables},
            headers=headers,
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()

        # Check for GraphQL errors
        if "errors" in data and data["errors"]:
            error_msgs = [str(e) for e in data["errors"]]
            error_text = "; ".join(error_msgs)
            logger.error(f"Saleor GraphQL error deleting address: {error_text}")
            result["error"] = "Saleor API error"
            return result

        # Check for mutation-level errors
        mutation_result = data.get("data", {}).get("addressDelete", {})
        if mutation_result.get("errors"):
            error_msgs = [e.get("message", "Unknown error") for e in mutation_result["errors"]]
            error_text = "; ".join(error_msgs)
            logger.error(f"Saleor address delete error: {error_text}")
            result["error"] = error_text
            return result

        result["success"] = True
        result["deleted_from_saleor"] = True
        logger.info(f"Successfully deleted billing address {billing_address.id} from Saleor")
        return result

    except requests.exceptions.Timeout:
        error_text = "Saleor request timeout"
        logger.error(f"Timeout deleting address from Saleor: {error_text}")
        result["error"] = error_text
        return result

    except requests.exceptions.RequestException as e:
        error_text = f"Saleor connection error: {str(e)[:100]}"
        logger.error(f"Request error deleting address from Saleor: {e}")
        result["error"] = error_text
        return result

    except Exception as e:
        error_text = f"Unexpected error: {str(e)[:100]}"
        logger.error(f"Unexpected error deleting address from Saleor: {e}", exc_info=True)
        result["error"] = error_text
        return result


def sync_billing_address_to_saleor(user, billing_address):
    """
    Sync a local BillingAddress to Saleor customer's default billing address.

    Args:
        user: Django user instance
        billing_address: BillingAddress model instance

    Returns:
        dict: {
            "success": bool,
            "saleor_synced": bool,
            "saleor_sync_error": str or None,
            "saleor_address_id": str or None (if synced/updated)
        }
    """
    saleor_url = getattr(settings, "SALEOR_API_URL", None)
    saleor_token = getattr(settings, "SALEOR_APP_TOKEN", None)

    result = {
        "success": True,
        "saleor_synced": False,
        "saleor_sync_error": None,
        "saleor_address_id": None,
    }

    # Saleor integration not enabled
    if not saleor_url or not saleor_token:
        logger.debug("Saleor not configured. Skipping address sync.")
        billing_address.saleor_sync_error = ""
        billing_address.saleor_synced_at = timezone.now()
        billing_address.save(update_fields=["saleor_sync_error", "saleor_synced_at"])
        return result

    # Ensure user has a Saleor customer ID
    if not hasattr(user, "profile") or not user.profile.saleor_customer_id:
        try:
            from users.saleor_sync import sync_user_to_saleor_sync
            sync_user_to_saleor_sync(user)
            user.refresh_from_db()
        except Exception as e:
            logger.error(f"Failed to sync user {user.id} to Saleor: {e}")
            result["saleor_sync_error"] = "Failed to create Saleor customer"
            billing_address.saleor_sync_error = result["saleor_sync_error"]
            billing_address.save(update_fields=["saleor_sync_error"])
            return result

    # Still no customer ID after sync attempt
    if not hasattr(user, "profile") or not user.profile.saleor_customer_id:
        error_msg = "Could not sync customer to Saleor"
        result["saleor_sync_error"] = error_msg
        billing_address.saleor_sync_error = error_msg
        billing_address.save(update_fields=["saleor_sync_error"])
        return result

    saleor_customer_id = user.profile.saleor_customer_id

    # Convert local address to Saleor format
    address_input = billing_address.to_saleor_input()

    headers = {
        "Authorization": f"Bearer {saleor_token}",
        "Content-Type": "application/json",
    }

    try:
        # Determine if we're creating or updating
        if billing_address.saleor_address_id:
            # Update existing Saleor address
            mutation = """
            mutation UpdateAddress($id: ID!, $input: AddressInput!) {
              addressUpdate(id: $id, input: $input) {
                address {
                  id
                }
                errors {
                  field
                  message
                }
              }
            }
            """
            variables = {
                "id": billing_address.saleor_address_id,
                "input": address_input,
            }
        else:
            # Create new Saleor address for this customer
            mutation = """
            mutation CreateAddress($userId: ID!, $input: AddressInput!) {
              addressCreate(userId: $userId, input: $input) {
                address {
                  id
                }
                errors {
                  field
                  message
                }
              }
            }
            """
            variables = {
                "userId": saleor_customer_id,
                "input": address_input,
            }

        response = requests.post(
            saleor_url,
            json={"query": mutation, "variables": variables},
            headers=headers,
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()

        # Check for GraphQL errors
        if "errors" in data and data["errors"]:
            error_msgs = [str(e) for e in data["errors"]]
            error_text = "; ".join(error_msgs)
            logger.error(f"Saleor GraphQL error syncing address: {error_text}")
            result["saleor_sync_error"] = "Saleor API error"
            billing_address.saleor_sync_error = result["saleor_sync_error"]
            billing_address.save(update_fields=["saleor_sync_error"])
            return result

        # Get the mutation result
        if billing_address.saleor_address_id:
            mutation_result = data.get("data", {}).get("addressUpdate", {})
        else:
            mutation_result = data.get("data", {}).get("addressCreate", {})

        # Check for mutation-level errors
        if mutation_result.get("errors"):
            error_msgs = [e.get("message", "Unknown error") for e in mutation_result["errors"]]
            error_text = "; ".join(error_msgs)
            logger.error(f"Saleor address mutation error: {error_text}")
            result["saleor_sync_error"] = error_text
            billing_address.saleor_sync_error = result["saleor_sync_error"]
            billing_address.save(update_fields=["saleor_sync_error"])
            return result

        address = mutation_result.get("address", {})
        address_id = address.get("id")

        if not address_id:
            logger.error("Saleor address creation/update returned no ID")
            result["saleor_sync_error"] = "No address ID returned from Saleor"
            billing_address.saleor_sync_error = result["saleor_sync_error"]
            billing_address.save(update_fields=["saleor_sync_error"])
            return result

        # Save new address ID if created
        if not billing_address.saleor_address_id:
            billing_address.saleor_address_id = address_id

        # Set this as the default billing address
        set_default_mutation = """
        mutation SetDefaultBillingAddress($userId: ID!, $addressId: ID!) {
          addressSetDefault(userId: $userId, addressId: $addressId, type: BILLING) {
            user {
              id
            }
            errors {
              field
              message
            }
          }
        }
        """
        set_default_variables = {
            "userId": saleor_customer_id,
            "addressId": address_id,
        }

        set_response = requests.post(
            saleor_url,
            json={"query": set_default_mutation, "variables": set_default_variables},
            headers=headers,
            timeout=10,
        )
        set_response.raise_for_status()
        set_data = set_response.json()

        # Check for set default errors
        if "errors" in set_data and set_data["errors"]:
            logger.warning(f"Failed to set default billing address in Saleor: {set_data['errors']}")
        else:
            set_result = set_data.get("data", {}).get("addressSetDefault", {})
            if set_result.get("errors"):
                logger.warning(f"Saleor addressSetDefault errors: {set_result['errors']}")

        # Success! Update the billing address model
        result["success"] = True
        result["saleor_synced"] = True
        result["saleor_address_id"] = address_id

        billing_address.saleor_address_id = address_id
        billing_address.saleor_synced_at = timezone.now()
        billing_address.saleor_sync_error = ""
        billing_address.save(
            update_fields=[
                "saleor_address_id",
                "saleor_synced_at",
                "saleor_sync_error",
            ]
        )

        logger.info(
            f"Successfully synced billing address for user {user.id} to Saleor: {address_id}"
        )
        return result

    except requests.exceptions.Timeout:
        error_text = "Saleor request timeout"
        logger.error(f"Timeout syncing address to Saleor: {error_text}")
        result["saleor_sync_error"] = error_text
        billing_address.saleor_sync_error = error_text
        billing_address.save(update_fields=["saleor_sync_error"])
        return result

    except requests.exceptions.RequestException as e:
        error_text = f"Saleor connection error: {str(e)[:100]}"
        logger.error(f"Request error syncing address to Saleor: {e}")
        result["saleor_sync_error"] = error_text
        billing_address.saleor_sync_error = error_text
        billing_address.save(update_fields=["saleor_sync_error"])
        return result

    except Exception as e:
        error_text = f"Unexpected error: {str(e)[:100]}"
        logger.error(f"Unexpected error syncing address to Saleor: {e}", exc_info=True)
        result["saleor_sync_error"] = error_text
        billing_address.saleor_sync_error = error_text
        billing_address.save(update_fields=["saleor_sync_error"])
        return result
