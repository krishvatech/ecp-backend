"""
WordPress profile synchronization service.

Handles:
- Syncing user data from WordPress to Event Platform
- Creating/updating local user profiles based on WordPress data
- Managing WordPress identity mapping
"""
import logging
from typing import Dict, Optional, Any, Tuple
from django.contrib.auth.models import User
from django.utils import timezone
from .models import UserProfile
from .wordpress_api import get_wordpress_client
from .email_utils import create_cognito_user, generate_temporary_password

logger = logging.getLogger(__name__)


def _extract_phone_from_wordpress(wp_user_data: Dict[str, Any]) -> Optional[str]:
    """
    Extract phone number from WordPress user data.

    WordPress might store phone in various formats:
    - Direct fields: phone, phone_number, contact_phone, mobile, telephone
    - WooCommerce billing: billing_phone (stored in user meta)
    - ACF fields: acf object with phone field
    - User meta fields: if custom registration stores it there

    Returns phone number string or None if not found
    """
    phone_field_names = ["phone", "phone_number", "contact_phone", "mobile", "telephone", "contact", "billing_phone"]

    # Check for direct fields
    for field_name in phone_field_names:
        value = wp_user_data.get(field_name)
        if value and isinstance(value, str) and value.strip():
            return value.strip()

    # Check for ACF fields
    acf_data = wp_user_data.get("acf", {})
    if isinstance(acf_data, dict):
        for field_name in phone_field_names:
            value = acf_data.get(field_name)
            if value and isinstance(value, str) and value.strip():
                return value.strip()

    # Check for meta fields
    meta_data = wp_user_data.get("meta", {})
    if isinstance(meta_data, dict):
        for field_name in phone_field_names:
            value = meta_data.get(field_name)
            if value and isinstance(value, str) and value.strip():
                return value.strip()

    logger.debug(f"No phone number found in WordPress user data")
    return None


def _extract_location_from_wordpress(wp_user_data: Dict[str, Any]) -> Dict[str, str]:
    """
    Extract location (city, country) from WordPress user data.

    WordPress might store location in various formats:
    - WooCommerce billing: billing_city, billing_country (in user meta)
    - ACF fields: Under acf object
    - User meta fields: if custom registration stores it there

    Returns dict with 'city' and 'country' keys (empty strings if not found)
    """
    location = {"city": "", "country": ""}

    # Check for direct fields
    city_value = wp_user_data.get("billing_city") or wp_user_data.get("city")
    country_value = wp_user_data.get("billing_country") or wp_user_data.get("country")

    if city_value and isinstance(city_value, str):
        location["city"] = city_value.strip()
    if country_value and isinstance(country_value, str):
        location["country"] = country_value.strip()

    # Check for ACF fields if not found yet
    acf_data = wp_user_data.get("acf", {})
    if isinstance(acf_data, dict):
        if not location["city"]:
            city_value = acf_data.get("billing_city") or acf_data.get("city")
            if city_value and isinstance(city_value, str):
                location["city"] = city_value.strip()
        if not location["country"]:
            country_value = acf_data.get("billing_country") or acf_data.get("country")
            if country_value and isinstance(country_value, str):
                location["country"] = country_value.strip()

    # Check for meta fields (includes WooCommerce billing fields)
    meta_data = wp_user_data.get("meta", {})
    if isinstance(meta_data, dict):
        if not location["city"]:
            city_value = meta_data.get("billing_city") or meta_data.get("city")
            if city_value and isinstance(city_value, str):
                location["city"] = city_value.strip()
        if not location["country"]:
            country_value = meta_data.get("billing_country") or meta_data.get("country")
            if country_value and isinstance(country_value, str):
                location["country"] = country_value.strip()

    if location["city"] or location["country"]:
        logger.debug(f"Extracted location from WordPress: {location}")

    return location


def _extract_social_links_from_wordpress(wp_user_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract social profile links from WordPress user data.

    WordPress might store social links in various formats:
    - Direct fields: facebook, instagram, linkedin, website, twitter, github, etc.
    - ACF fields: acf object with social profile fields
    - Nested in _links or other metadata
    - User meta fields (if site uses custom registration)

    NOTE: For social profile links to sync, the WordPress site must expose these fields
    via the REST API. This requires one of:
    1. ACF plugin with fields configured to show in REST API
    2. Custom registration with register_rest_field() or register_meta()
    3. WordPress plugin that exposes user metadata in REST API

    The Event Platform will automatically sync these fields when they're available.

    Returns a dict with keys like: facebook, instagram, linkedin, website, x, github
    """
    links = {}

    # Check for direct fields (facebook, instagram, linkedin, website, etc.)
    social_field_mapping = {
        "facebook": ["facebook", "fb_url", "facebook_url", "facebook_profile", "fb", "facebook_link"],
        "instagram": ["instagram", "instagram_url", "instagram_profile", "instagram_handle"],
        "linkedin": ["linkedin", "linkedin_url", "linkedin_profile", "linkedin_link"],
        "website": ["website", "personal_website", "website_url", "web", "site_url", "url"],  # Added 'url' for WordPress
        "twitter": ["twitter", "twitter_url", "twitter_handle", "x_url", "x_handle"],
        "x": ["x", "x_url", "x_handle"],
        "github": ["github", "github_url", "github_profile", "github_link"],
    }

    # Try to extract from direct fields (simple key-value pairs)
    for link_type, field_names in social_field_mapping.items():
        for field_name in field_names:
            value = wp_user_data.get(field_name)
            if value and isinstance(value, str) and value.strip():
                links[link_type] = value.strip()
                break  # Found value for this link type, move to next

    # Check for ACF fields (if WordPress uses Advanced Custom Fields)
    acf_data = wp_user_data.get("acf", {})
    if isinstance(acf_data, dict):
        for link_type, field_names in social_field_mapping.items():
            if link_type not in links:  # Only add if not already found
                for field_name in field_names:
                    value = acf_data.get(field_name)
                    if value and isinstance(value, str) and value.strip():
                        links[link_type] = value.strip()
                        break

    # Check for nested ACF groups (e.g., acf.social_profiles.facebook)
    if isinstance(acf_data, dict):
        for link_type, field_names in social_field_mapping.items():
            if link_type not in links:
                # Look for nested structures like social_profiles, social, social_media, etc.
                for prefix in ["social_profiles", "social", "social_media", "socials"]:
                    nested = acf_data.get(prefix, {})
                    if isinstance(nested, dict):
                        for field_name in field_names:
                            value = nested.get(field_name)
                            if value and isinstance(value, str) and value.strip():
                                links[link_type] = value.strip()
                                break
                    if link_type in links:
                        break

    # Check for meta fields (WordPress user metadata)
    meta_data = wp_user_data.get("meta", {})
    if isinstance(meta_data, dict):
        for link_type, field_names in social_field_mapping.items():
            if link_type not in links:
                for field_name in field_names:
                    value = meta_data.get(field_name)
                    if value and isinstance(value, str) and value.strip():
                        links[link_type] = value.strip()
                        break

    # Check for _links metadata (if structured differently)
    wp_links = wp_user_data.get("_links", {})
    if isinstance(wp_links, dict):
        for link_type, field_names in social_field_mapping.items():
            if link_type not in links:
                for field_name in field_names:
                    value = wp_links.get(field_name)
                    if value:
                        if isinstance(value, list) and len(value) > 0:
                            url = value[0].get("href") if isinstance(value[0], dict) else value[0]
                            if isinstance(url, str) and url.strip():
                                links[link_type] = url.strip()
                                break
                        elif isinstance(value, str) and value.strip():
                            links[link_type] = value.strip()
                            break

    logger.debug(f"Extracted social links from WordPress: {links}")
    return links


class WordPressProfileSyncService:
    """Service to sync WordPress user profiles to Event Platform."""

    def __init__(self):
        self.wp_client = get_wordpress_client()

    def sync_user_from_wordpress(
        self, wp_user_data: Dict[str, Any], override_email: Optional[str] = None
    ) -> Tuple[Optional[User], bool]:
        """
        Sync or create a user from WordPress data.

        Args:
            wp_user_data: User data from WordPress
            override_email: If provided, use this email instead of WordPress email

        Returns:
            Tuple of (user_object, is_newly_created)
        """
        try:
            wp_user_id = wp_user_data.get("id")
            wp_email = override_email or wp_user_data.get("email")
            # WordPress API returns 'slug' not 'username'
            wp_username = wp_user_data.get("username") or wp_user_data.get("slug", "")
            wp_name = wp_user_data.get("name", "")

            if not wp_user_id:
                logger.error(f"Invalid WordPress user data: missing user ID")
                return None, False

            # If no email provided, construct from username/slug or use placeholder
            if not wp_email and wp_username:
                # Try to construct email from username/slug
                wp_email = f"{wp_username}@wordpress.local"
                logger.warning(f"WordPress user {wp_user_id} has no email, using constructed: {wp_email}")
            elif not wp_email:
                logger.error(f"Invalid WordPress user data {wp_user_id}: missing email, username, and slug")
                return None, False

            # Try to find existing user by WordPress ID first
            try:
                profile = UserProfile.objects.get(wordpress_id=wp_user_id)
                user = profile.user
                is_new = False
            except UserProfile.DoesNotExist:
                # Try to find by email
                try:
                    user = User.objects.get(email=wp_email)
                    profile = user.profile
                    is_new = False
                except User.DoesNotExist:
                    # Create new user
                    user = self._create_user_from_wordpress(wp_user_data)
                    profile = user.profile
                    is_new = True

            # Update user and profile with WordPress data
            self._update_user_from_wordpress(user, profile, wp_user_data)

            # Ensure Cognito user exists (create if needed)
            self._ensure_cognito_user_exists(user)

            return user, is_new

        except Exception as e:
            logger.error(f"Error syncing WordPress user {wp_user_data.get('id')}: {str(e)}", exc_info=True)
            return None, False

    def _create_user_from_wordpress(self, wp_user_data: Dict[str, Any]) -> User:
        """Create a new Django user from WordPress data."""
        wp_email = wp_user_data.get("email")
        wp_name = wp_user_data.get("name", "")
        # WordPress API returns 'slug' not 'username'
        wp_username = wp_user_data.get("username") or wp_user_data.get("slug", "")

        # Construct email from username/slug if not provided by WordPress
        if not wp_email and wp_username:
            wp_email = f"{wp_username}@wordpress.local"

        # Ensure unique username
        base_username = wp_username or (wp_email.split("@")[0] if wp_email else "wordpress_user")
        username = base_username
        counter = 1

        while User.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1

        user = User.objects.create_user(
            username=username,
            email=wp_email,
            first_name=wp_name.split()[0] if wp_name else "",
            last_name=" ".join(wp_name.split()[1:]) if wp_name and " " in wp_name else "",
        )

        logger.info(f"Created new user {user.id} from WordPress user {wp_user_data.get('id')}")

        # Create Cognito user with temporary password
        try:
            temp_password = generate_temporary_password()
            first_name = wp_name.split()[0] if wp_name else ""
            last_name = " ".join(wp_name.split()[1:]) if wp_name and " " in wp_name else ""

            cognito_created = create_cognito_user(
                username=username,
                email=wp_email,
                temp_password=temp_password,
                first_name=first_name,
                last_name=last_name
            )

            if cognito_created:
                # Store temporary password in user profile for future authentication
                user.profile.cognito_temp_password = temp_password
                user.profile.save()
                logger.info(f"Created Cognito user for Django user {user.id}: {username}")
            else:
                logger.warning(f"Failed to create Cognito user for Django user {user.id}: {username}")
        except Exception as e:
            logger.error(f"Error creating Cognito user for {username}: {str(e)}", exc_info=True)

        return user

    def _update_user_from_wordpress(
        self, user: User, profile: UserProfile, wp_user_data: Dict[str, Any]
    ) -> None:
        """Update user and profile with WordPress data."""
        wp_user_id = wp_user_data.get("id")
        wp_email = wp_user_data.get("email")
        wp_name = wp_user_data.get("name", "")
        wp_description = wp_user_data.get("description", "")
        wp_avatar_url = wp_user_data.get("avatar_urls", {}).get("96") if wp_user_data.get("avatar_urls") else ""

        # Log available fields for debugging
        logger.debug(f"WordPress user {wp_user_id} data fields: {list(wp_user_data.keys())}")

        # Construct email from username/slug if not provided by WordPress
        wp_username = wp_user_data.get("username") or wp_user_data.get("slug", "")
        if not wp_email and wp_username:
            wp_email = f"{wp_username}@wordpress.local"

        # Update User fields
        user_updated = False
        # Only update email if we have a valid value (not None/null)
        if wp_email and user.email != wp_email:
            user.email = wp_email
            user_updated = True

        if wp_name:
            name_parts = wp_name.split()
            new_first_name = name_parts[0]
            new_last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else ""
            if user.first_name != new_first_name or user.last_name != new_last_name:
                user.first_name = new_first_name
                user.last_name = new_last_name
                user_updated = True

        if user_updated:
            user.save()

        # Update UserProfile fields
        profile_updated = False

        if profile.wordpress_id != wp_user_id:
            profile.wordpress_id = wp_user_id
            profile_updated = True

        if profile.wordpress_email != wp_email:
            profile.wordpress_email = wp_email
            profile_updated = True

        # WordPress API returns 'slug' not 'username'
        wp_username = wp_user_data.get("username") or wp_user_data.get("slug", "")
        if profile.wordpress_username != wp_username:
            profile.wordpress_username = wp_username
            profile_updated = True

        # Always update full_name from WordPress (master source)
        if wp_name and profile.full_name != wp_name:
            profile.full_name = wp_name
            profile_updated = True

        # Only update bio if empty (allow user customization on platform)
        if wp_description and not profile.bio:
            profile.bio = wp_description
            profile_updated = True

        # Always update avatar from WordPress
        if wp_avatar_url and profile.wordpress_avatar_url != wp_avatar_url:
            profile.wordpress_avatar_url = wp_avatar_url
            profile_updated = True

        # Extract and sync social profile links from WordPress
        wp_social_links = _extract_social_links_from_wordpress(wp_user_data)

        # Extract and sync phone number from WordPress
        wp_phone = _extract_phone_from_wordpress(wp_user_data)

        # Extract and sync location (city, country) from WordPress
        wp_location = _extract_location_from_wordpress(wp_user_data)

        if wp_social_links or wp_phone:
            # Merge new links with existing links (preserve platform-specific links)
            existing_links = profile.links or {}
            links_changed = False

            # Update only the social profile links, keep other data like contact info
            for link_type, url in wp_social_links.items():
                if existing_links.get(link_type) != url:
                    existing_links[link_type] = url
                    links_changed = True

            # Update phone number if extracted from WordPress
            if wp_phone and existing_links.get("phone") != wp_phone:
                existing_links["phone"] = wp_phone
                links_changed = True

            if links_changed:
                profile.links = existing_links
                profile_updated = True
                if wp_social_links:
                    logger.info(f"Updated social links for user {user.id}: {wp_social_links}")
                if wp_phone:
                    logger.info(f"Updated phone number for user {user.id}: {wp_phone}")

        # Update location from WordPress (only if not set by user on platform)
        if wp_location.get("city") or wp_location.get("country"):
            # Build location string from city and country
            location_parts = []
            if wp_location.get("city"):
                location_parts.append(wp_location["city"])
            if wp_location.get("country"):
                location_parts.append(wp_location["country"])
            location_str = ", ".join(location_parts)

            # Only update location if empty (allow user customization on platform)
            if not profile.location and location_str:
                profile.location = location_str
                profile_updated = True
                logger.info(f"Updated location for user {user.id}: {location_str}")

        if not profile.wordpress_synced_at or profile.wordpress_sync_status != "synced":
            profile.wordpress_synced_at = timezone.now()
            profile.wordpress_sync_status = "synced"
            profile_updated = True

        if profile_updated:
            profile.save()
            logger.info(f"Updated profile for user {user.id} from WordPress")

    def _ensure_cognito_user_exists(self, user: User) -> None:
        """
        Ensure a Cognito user exists for the Django user.
        Creates one if it doesn't exist (handles existing Django users without Cognito).
        """
        try:
            temp_password = generate_temporary_password()
            cognito_created = create_cognito_user(
                username=user.username,
                email=user.email,
                temp_password=temp_password,
                first_name=user.first_name,
                last_name=user.last_name
            )

            if cognito_created:
                # Store temporary password in user profile for future authentication
                user.profile.cognito_temp_password = temp_password
                user.profile.save()
                logger.info(f"Ensured Cognito user exists for Django user {user.id}: {user.username}")
            else:
                logger.warning(f"Failed to ensure Cognito user for Django user {user.id}: {user.username}")
        except Exception as e:
            logger.error(f"Error ensuring Cognito user for {user.username}: {str(e)}", exc_info=True)

    def fetch_and_sync_user_by_email(self, email: str) -> Tuple[Optional[User], bool]:
        """
        Fetch user from WordPress by email and sync locally.

        Returns:
            Tuple of (user_object, is_newly_created)
        """
        wp_user_data = self.wp_client.get_user_by_email(email)
        if not wp_user_data:
            logger.warning(f"WordPress user not found for email: {email}")
            return None, False

        return self.sync_user_from_wordpress(wp_user_data)

    def fetch_and_sync_user_by_id(self, wp_user_id: int) -> Tuple[Optional[User], bool]:
        """
        Fetch user from WordPress by ID and sync locally.

        Returns:
            Tuple of (user_object, is_newly_created)
        """
        wp_user_data = self.wp_client.get_user_by_id(wp_user_id)
        if not wp_user_data:
            logger.warning(f"WordPress user not found for ID: {wp_user_id}")
            return None, False

        return self.sync_user_from_wordpress(wp_user_data)

    def handle_wordpress_webhook(self, event: str, user_data: Dict[str, Any]) -> bool:
        """
        Handle incoming WordPress webhook for user updates.

        Events:
        - user_created: New user registered
        - user_updated: User profile updated
        - user_deleted: User removed

        Returns:
            True if successfully processed, False otherwise
        """
        try:
            wp_user_id = user_data.get("id") or user_data.get("user_id")

            if event in ["user_created", "user_updated"]:
                user, is_new = self.sync_user_from_wordpress(user_data)
                if user:
                    action = "created" if is_new else "updated"
                    logger.info(f"WordPress user {action}: {user.id}")
                    return True
                return False

            elif event == "user_deleted":
                try:
                    profile = UserProfile.objects.get(wordpress_id=wp_user_id)
                    user = profile.user
                    # Deactivate instead of deleting
                    user.is_active = False
                    user.save()
                    profile.wordpress_sync_status = "deleted"
                    profile.save()
                    logger.info(f"Deactivated user {user.id} after WordPress deletion")
                    return True
                except UserProfile.DoesNotExist:
                    logger.warning(f"User not found for WordPress ID {wp_user_id}")
                    return False

            else:
                logger.warning(f"Unknown webhook event: {event}")
                return False

        except Exception as e:
            logger.error(f"Error handling WordPress webhook ({event}): {str(e)}", exc_info=True)
            return False


# Singleton instance
_sync_service = None


def get_profile_sync_service() -> WordPressProfileSyncService:
    """Get or create profile sync service."""
    global _sync_service
    if _sync_service is None:
        _sync_service = WordPressProfileSyncService()
    return _sync_service
