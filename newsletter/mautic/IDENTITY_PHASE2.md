# ECP → Mautic per-user execution — Phase 2

Phase 1 built the identity foundation and left it dormant. Phase 2 activates it
for exactly two interactive operations, behind a feature flag that defaults to
off.

## Request flow (flag on, actor mapped)

```
Cognito User A
  → ECP request.user = User A
  → IsStaffOrSuperuser (Marketing Hub rule, unchanged)
  → MauticUserConnection lookup by Django user pk
  → get_mautic_client(actor=User A, purpose=INTERACTIVE) → ASSERTED_USER
  → POST /api/ecp/bridge/campaigns/new
        Basic Auth:                ECP service account   (required)
        X-ECP-Identity-Assertion:  RS256 assertion, ≤90s (required)
  → Mautic "api" firewall authenticates the service account
  → EcpIdentityVerifier: signature, alg, kid, iss, aud, iat/exp, jti, purpose
  → DoctrineJtiReplayStore: atomic single-use consume
  → UserRepository loads Mautic user; must be published
  → EcpActingUserContext::runAs → token swapped to Mautic User A
  → sub-request to the native campaign API
        CorePermissions evaluates as User A
        FormModel::setTimestamps stamps createdBy / modifiedBy = User A
  → previous (service) token restored in a finally block
```

With the flag off the client keeps using the native endpoints as the service
account, exactly as in Phase 1. With the flag **on**, per-user execution is
mandatory for interactive work: if the mapping or the signing configuration is
missing, the operation is refused rather than run as the service account.

## Why this shape

* **Two independent factors.** The bridge routes live under Mautic's `^/api`
  firewall, so the service account is authenticated before the controller runs;
  the assertion is then required on top. Neither alone is sufficient.
* **No duplicated campaign logic.** The bridge forwards to Mautic's own
  `CampaignApiController` as a sub-request. Symfony skips the firewall on
  sub-requests, so the acting-user token stays in place while native
  validation, permissions, form handling and attribution run unchanged.
* **Attribution is a side effect of the real security context**, never written
  by hand: `FormModel::setTimestamps()` reads `UserHelper::getUser()`, which
  reads the token storage.
* **Strict allowlist.** Two routes only (campaign create, campaign update).
  There is no generic proxy.

## Replay protection

`DoctrineJtiReplayStore` inserts `sha256(jti)` into
`ecp_identity_assertion_uses`, which has a unique index. The database decides
the winner, so acceptance is exactly-once across every Mautic node. Any storage
error other than the unique violation is rethrown, so the verifier fails closed.
Expired rows are purged opportunistically (~2% of calls) and via
`purgeExpired()`.

This replaces the Phase 1 `CacheJtiReplayStore`, which was check-then-set and
filesystem-local. That class has been removed so there is no ambiguity about
which implementation is in use.

The table is created from the plugin's Doctrine entity (`EcpIdentityAssertionUse`)
by Mautic's normal plugin install/reload. It is **not** created automatically at
runtime.

## Operations migrated

| Operation | ECP entry point | Execution |
|---|---|---|
| Campaign create | `NewsletterAdminMauticCampaignListCreateView.post` | INTERACTIVE → asserted user (flag on) |
| Campaign update | `NewsletterAdminMauticCampaignDetailView.patch` | INTERACTIVE → asserted user (flag on) |

Everything else is deliberately unchanged and stays on the service account:
campaign read/delete/events/builder, sends and scheduling, emails, contacts,
segments, templates, points, companies, fields, tags, analytics, dashboard,
diagnostics, webhooks, and every Celery/beat job.

Reads made by the migrated views (for example campaign-builder capabilities)
also stay on the service account: the assertion is attached only to the two
bridge paths.

## Feature flag

`ECP_MAUTIC_PER_USER_EXECUTION_ENABLED`, default `false`.

| State | Behaviour |
|---|---|
| off | Identical to Phase 1. No assertion is minted or sent, mapping state is irrelevant. |
| on, actor mapped, signing configured | The two campaign paths use the bridge as the mapped Mautic user. |
| on, no/disabled mapping | `MauticUserConnectionMissingError` / `MauticUserConnectionInactiveError`; the operation is refused. |
| on, signing not configured | `MauticIdentityConfigurationError`; the operation is refused. |

Failing closed is deliberate. Once an operator turns the flag on they expect
per-user attribution, so silently executing a human action as the shared
service account would corrupt the audit trail. Background, system and
read-only contexts are unaffected and keep running on the service account.

Roll out by provisioning mappings **before** enabling the flag.

## Configuration

ECP (environment):

```
ECP_MAUTIC_PER_USER_EXECUTION_ENABLED=false
ECP_MAUTIC_IDENTITY_PRIVATE_KEY=       # RS256 private key, 2048+ bits
ECP_MAUTIC_IDENTITY_KEY_ID=
ECP_MAUTIC_IDENTITY_ISSUER=ecp
ECP_MAUTIC_IDENTITY_AUDIENCE=ecp-mautic
ECP_MAUTIC_IDENTITY_TTL_SECONDS=90
```

Mautic (`config/local.php` or `MAUTIC_CONFIG_PARAMETERS`): `ecp_identity_public_key`
(public half only — the verifier refuses a private key), `ecp_identity_key_id`,
`ecp_identity_issuer`, `ecp_identity_audience`, `ecp_identity_clock_skew_seconds`.

## Error handling

| Condition | ECP result |
|---|---|
| No mapping / disabled mapping (flag on) | Refused; HTTP 503 from the existing identity handler (logged as a warning) |
| Signing not configured (flag on) | Refused; HTTP 503 (logged as an error) |
| No mapping / disabled mapping (flag off) | Service account, unchanged Phase 1 behaviour |
| Bridge rejects identity or permissions (401/403) | `MauticBridgeRejectedError` → HTTP 403, generic message |
| Bridge unavailable / misconfigured (503) | Provider error → HTTP 502/503, generic message |
| Verifier misconfigured in Mautic | 503; never falls back to executing as the service account |

Responses and logs never contain the assertion, its signature, keys, or
credentials. Logs carry the ECP user id, Mautic user id, jti, operation and
outcome only.

## Not in Phase 2

Automatic Mautic user provisioning, role synchronization, browser SSO, any
further operations, frontend changes, bulk mapping, key rotation tooling,
production keys or deployment.
