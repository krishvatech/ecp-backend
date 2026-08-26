# CRM integration contract

The first milestone synchronizes ECP users to Salesforce. Newsletter, event,
order, payment, and Salesforce-to-ECP synchronization are outside this scope.

Initial contract:

- Direction: ECP to Salesforce only.
- Salesforce object: `Contact`.
- Idempotent key: Salesforce external-ID field
  `IMAA_Connect_User_ID__c`, containing the Django user ID.
- User data: `first_name`, `last_name`, and `email` from Django `User`.
- Profile data: `company`, `job_title`, `location_country`, and
  `location_country_code` from `UserProfile`.
- Delivery: asynchronous after the ECP database transaction commits.
- Failure isolation: Salesforce failures must never fail user signup or profile
  updates.
- Secrets: environment variables or a secret manager; never database payloads
  or logs.

Before enabling a production Salesforce connection, the Salesforce owner must
confirm that the Contact external-ID field exists and approve the destination
fields for company and country code.

## Salesforce environment configuration

The adapter uses the OAuth client-credentials flow. Configuring environment
variables does not enable synchronization; an active `CRMConnection` and the
later worker phase are also required.

Required:

- `SALESFORCE_CLIENT_ID`
- `SALESFORCE_CLIENT_SECRET`

Defaults and optional field mappings:

- `SALESFORCE_LOGIN_URL=https://login.salesforce.com`
- `SALESFORCE_API_VERSION=v61.0`
- `SALESFORCE_REQUEST_TIMEOUT=15`
- `SALESFORCE_CONTACT_EXTERNAL_ID_FIELD=IMAA_Connect_User_ID__c`
- `SALESFORCE_CONTACT_COMPANY_FIELD=Company__c`
- `SALESFORCE_CONTACT_COUNTRY_CODE_FIELD=`
- `SALESFORCE_CONTACT_PROFILE_STATUS_FIELD=`
- `SALESFORCE_CONTACT_ACTIVE_FIELD=`

The Salesforce Connected App must have the client-credentials flow enabled.
The external-ID Contact field must be marked as an External ID and unique.
Deactivation events remain rejected unless an active or profile-status field
is configured, preventing accidental deletion or misleading synchronization.

## Worker configuration

CRM delivery is processed by the existing Celery infrastructure. Optional
controls are:

- `CRM_SYNC_ENABLED=false`
- `CRM_SYNC_STAFF_USERS=false`
- `CRM_SYNC_IMPORTED_USERS=true`
- `CRM_SYNC_MAX_RETRIES=5`
- `CRM_SYNC_RETRY_BASE_SECONDS=30`
- `CRM_SYNC_RETRY_MAX_SECONDS=3600`
- `CRM_SYNC_PROCESSING_TIMEOUT_SECONDS=600`

Temporary failures use bounded exponential backoff. A duplicate worker cannot
claim an event already being processed, while a processing event older than
the timeout can be recovered after a worker crash. Permanent failures and
exhausted retries remain visible in `CRMSyncEvent` for administrative review.

`CRM_SYNC_ENABLED` is the rollout switch and defaults to disabled. Enabling it
still sends nothing unless an active `CRMConnection` exists. Superusers,
load-test/system accounts, placeholder WordPress addresses, and (by default)
staff users are excluded. User and relevant profile changes create events only
after their database transactions commit. If Celery dispatch fails, the user
request remains successful and the pending event is retained for recovery.

Operations available to platform administrators:

- `CRMConnection` admin action: test selected connections and persist health.
- `CRMSyncEvent` admin action: reset and retry selected non-successful events.
- `python manage.py dispatch_crm_sync_events --batch-size 100` for manual
  recovery of pending, due-retry, and stale-processing events.
- When CRM sync is enabled, Celery Beat dispatches due events every minute.

The rollout flag is also enforced inside the worker. Turning it off prevents
already queued tasks and manual requeues from contacting the provider; their
pending state is retained until synchronization is enabled again.
