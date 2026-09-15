# ECP → Mautic user identity — Phase 1 foundation

Phase 1 adds the identity building blocks. **It does not change how any live
Mautic call authenticates.** Every call still uses `MAUTIC_USERNAME` /
`MAUTIC_PASSWORD`, the Basic Auth service account.

## Components

| Component | Location | Phase 1 behaviour |
|---|---|---|
| `MauticUserConnection` | `newsletter/models.py` (migration `0008`) | Maps an ECP user (Django pk) to a Mautic user id. At most one active row per ECP user and per Mautic user. |
| Connection services | `newsletter/mautic_identity_services.py` | Connect (transactional, keeps disabled history), disable, status. They never create Mautic users. |
| Execution context and client factory | `newsletter/mautic/identity.py` | `get_mautic_client(actor, purpose)` records metadata and always returns a service-account client. |
| Assertion signer | `newsletter/mautic/identity_assertion.py` | RS256, 10–120s TTL, unique `jti`. Only for `interactive`. Nothing sends it yet. |
| Status API | `GET /api/newsletter/admin/settings/mautic-identity/status/` | Staff-only. Returns non-sensitive state. |
| Mautic verifier | `ECP Mautic/plugins/EcpMarketingBridgeBundle/Identity/` | A verification service only. It creates no session and no route, and it does not change API auth. |

## Identity decisions

* **ECP subject = Django `User.pk`** (the `sub` claim). `cognito_sub` is not
  used as the key: `CognitoIdentity` is a ForeignKey, so one user may have
  several subs, and `users/cognito_auth.py` can re-point a sub during recovery.
  Cognito still authenticates the request and resolves `request.user`; the
  assertion is minted from that already-authenticated user.
* **Mautic identity = `mautic_user_id`**. Username, email, display name and
  role are cached display metadata and are never used to resolve identity.
* **Email is never an identity key** on either side.

## Assertion claims

```
header: {"alg": "RS256", "typ": "ecp-identity+jwt", "kid": <ECP_MAUTIC_IDENTITY_KEY_ID>}
claims: {iss, aud, sub, mautic_user_id, purpose: "interactive", iat, exp, jti}
```

No Cognito token, Mautic credential, password or email is included. Only the
`jti`, user ids and `kid` are logged. The token itself is never logged.

## Replay protection

The Mautic verifier consumes each `jti` through `JtiReplayStoreInterface`,
and only after every other check has passed. A forged token therefore cannot
burn a legitimate `jti`.

The Phase 1 implementation, `CacheJtiReplayStore`, uses Mautic's existing
`CacheProviderInterface`, so no new service is needed. It keeps each `jti`
until `exp` plus the clock skew.

That store has two limits:

* It does check-then-set, which is not atomic.
* With the default filesystem cache adapter, the cache is local to each
  container.

Before Phase 2 accepts assertions on more than one Mautic web node, swap in an
atomic shared store behind the same interface. Either works:

* a DB table with a unique `jti` column (insert-or-fail)
* Redis `SET NX EX`

## Execution-context classification of current call sites

Classification is recorded here. Call sites still construct `MauticClient()`
directly, and existing tests patch those module-level names, so they are
deliberately unchanged in Phase 1.

| Call site | Context (target) |
|---|---|
| `native_campaign_views.py` create/update/delete campaign, events | INTERACTIVE |
| `campaign_services.sync_campaign_to_mautic` / `sync_campaign_draft_to_mautic` (admin sync/save) | INTERACTIVE |
| `campaign_services.send_campaign_test_email` | INTERACTIVE |
| `campaign_services.delete_draft_campaign` | INTERACTIVE |
| `campaign_services.schedule_campaign` / `cancel_scheduled_campaign` / `request_campaign_send` (ECP-side request only) | INTERACTIVE (no Mautic call; the actual send is BACKGROUND) |
| `template_views.py` create/update/delete/duplicate | INTERACTIVE |
| `template_views.py` list/get/preview/categories/themes | INTERACTIVE (read) |
| `admin_views.py` stages, segments (create/patch/delete, contacts add/remove), category link/sync | INTERACTIVE |
| `admin_views._ensure_category_segment` | INTERACTIVE when invoked from a staff request |
| `contact_services.py` create/update/notes/DNC/tags/stage/bulk stage | INTERACTIVE |
| `contact_services.py` list/get/activity/engagement/companies/fields | INTERACTIVE (read) |
| `company_services.py`, `field_services.py`, `tag_services.py` mutations | INTERACTIVE |
| `point_views.py`, `point_group_views.py`, `point_trigger_views.py` mutations | INTERACTIVE |
| `mautic_analytics_services.py`, `analytics_services.py`, `mautic_dashboard_services.py` | READ_ONLY |
| `mautic_diagnostics_services.py` (health check, capabilities) | SYSTEM |
| `processor.process_newsletter_sync_event` (Celery `newsletter.process_sync_event`) | BACKGROUND |
| `campaign_send_processor.process_campaign_send_event` + `sync_campaign_for_worker_delivery` | BACKGROUND |
| `tasks.dispatch_due_*` (beat: sync events, send events, scheduled campaigns) | BACKGROUND |
| `webhooks.MauticNewsletterWebhookView` (inbound, HMAC-verified; no outbound client) | BACKGROUND |

BACKGROUND work may keep `requested_by` / `actor_id` as audit metadata. It must
never mint an identity assertion: `issue_identity_assertion` refuses any
non-interactive purpose.

## Explicitly not done in Phase 1

* Switching any Mautic call to per-user execution, or security-context
  switching in Mautic
* Automatic Mautic user provisioning, and role synchronization
* Mautic browser SSO
* Removing service-account auth
* Frontend changes
* Bulk user mapping
* Production key creation or deployment
