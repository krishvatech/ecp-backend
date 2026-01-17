from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.conf import settings
import requests
import json

User = get_user_model()

class Command(BaseCommand):
    help = "Syncs valid ECP users to Saleor as Customers (or Staff)."

    def handle(self, *args, **options):
        saleor_url = settings.SALEOR_API_URL
        saleor_token = settings.SALEOR_APP_TOKEN

        if not saleor_token:
            self.stdout.write(self.style.ERROR("SALEOR_APP_TOKEN is missing in settings needed to perform sync."))
            return

        headers = {
            "Authorization": f"Bearer {saleor_token}",
            "Content-Type": "application/json"
        }

        self.stdout.write(f"Syncing users to Saleor at {saleor_url}...")

        users = User.objects.all().order_by("id")
        count = 0
        total = users.count()

        for user in users:
            if not user.email:
                continue
            
            # Simple progress
            self.stdout.write(f"Processing ({count}/{total}): {user.email}")
            
            # 1. Check if user exists
            if self.check_user_exists(user.email, saleor_url, headers):
                self.stdout.write(self.style.SUCCESS(f" - Exists: {user.email}"))
            else:
                # 2. Create user (Customer or Staff)
                # For simplicity, we sync everyone as Customer first.
                # Staff sync needs specific permission groups which is complex to guess.
                if self.create_customer(user, saleor_url, headers):
                     self.stdout.write(self.style.SUCCESS(f" - Created Customer: {user.email}"))
                else:
                     self.stdout.write(self.style.ERROR(f" - Failed to create: {user.email}"))
            
            count += 1

    def check_user_exists(self, email, url, headers):
        # Query customers
        query = """
        query CheckCustomer($email: String!) {
          customers(filter: {search: $email}, first: 1) {
            edges {
              node {
                id
                email
              }
            }
          }
          staffUsers(filter: {search: $email}, first: 1) {
             edges {
              node {
                id
                email
              }
            }
          }
        }
        """
        payload = {"query": query, "variables": {"email": email}}
        try:
            r = requests.post(url, json=payload, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                cust_edges = data.get("data", {}).get("customers", {}).get("edges", [])
                staff_edges = data.get("data", {}).get("staffUsers", {}).get("edges", [])
                # Check if fetched email actually matches (search is fuzzy)
                for edge in cust_edges:
                    if edge["node"]["email"].lower() == email.lower():
                        return True
                for edge in staff_edges:
                    if edge["node"]["email"].lower() == email.lower():
                        return True
            return False
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error checking user {email}: {e}"))
            return False

    def create_customer(self, user, url, headers):
        mutation = """
        mutation CreateCustomer($input: UserCreateInput!) {
          customerCreate(input: $input) {
            user {
              id
              email
            }
            errors {
              field
              message
              code
            }
          }
        }
        """
        
        # Profile fields
        first_name = user.first_name or ""
        last_name = user.last_name or ""
        # user.profile might not exist if created via pure admin, handle gracefully
        try:
            if hasattr(user, 'profile'):
                if not first_name: first_name = user.profile.full_name.split(" ")[0]
                if not last_name: last_name = " ".join(user.profile.full_name.split(" ")[1:])
        except:
            pass
            
        if not first_name: first_name = user.username
        
        variables = {
            "input": {
                "email": user.email,
                "firstName": first_name,
                "lastName": last_name,
                "isActive": True,
                # "confirmed": True # Some versions might need this or just isActive
            }
        }
        
        try:
            r = requests.post(url, json={"query": mutation, "variables": variables}, headers=headers)
            if r.status_code == 200:
                data = r.json()
                errors = data.get("data", {}).get("customerCreate", {}).get("errors", [])
                if errors:
                    self.stdout.write(self.style.ERROR(f"GraphQL Errors: {errors}"))
                    return False
                return True
            else:
                self.stdout.write(self.style.ERROR(f"HTTP Error: {r.text}"))
                return False
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Exception creating user: {e}"))
            return False
