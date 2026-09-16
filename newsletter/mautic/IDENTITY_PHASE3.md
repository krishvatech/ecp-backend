# ECP → Mautic identity — Phase 3 operational layer

Phase 1 built the identity foundation, Phase 2 activated per-user execution for
campaign create/update. Phase 3 makes that operable: mapping management, clear
failures, an audit trail, and readiness diagnostics.

Runtime behaviour is unchanged when
`ECP_MAUTIC_PER_USER_EXECUTION_ENABLED=false` (the default).

## User mapping lifecycle

```
(no mapping)
   │  POST   …/mautic-identity/connections/          {ecp_user_id, mautic_user_id, …}
   ▼
 active ──── POST …/connections/{id}/deactivate/ ──▶ disabled
   ▲                                                    │
   └──────── POST …/connections/{id}/activate/ ─────────┘
```

Invariants, enforced by partial unique indexes and re-checked on activate:

* one **active** mapping per ECP user, and per Mautic user;
* the target must be an active Marketing Hub staff user;
* `mautic_user_id` is authoritative — email is never an identity key;
* disabled rows are retained as history, never deleted;
* timestamps kept: `connected_at`, `disabled_at`, `last_verified_at`,
  `created_at`, `updated_at`.

A mapping stores **no credentials**: an existing Mautic user id plus display
metadata only.

### Endpoints (all staff-only, `IsStaffOrSuperuser`)

| Method | Path | Purpose |
|---|---|---|
| GET | `…/mautic-identity/status/` | Connection state of the calling user, and how their next interactive action would authenticate |
| GET | `…/mautic-identity/connections/` | List all mappings (`is_active`, `ecp_user_id`, paging) |
| POST | `…/mautic-identity/connections/` | Create or refresh a mapping |
| GET | `…/mautic-identity/connections/{id}/` | One mapping |
| POST | `…/mautic-identity/connections/{id}/activate/` | Re-enable |
| POST | `…/mautic-identity/connections/{id}/deactivate/` | Disable (optional `reason`) |
| GET | `…/mautic-identity/audit/` | Query the audit trail |

Prefix: `/api/newsletter/admin/settings/`.

`status/` derives `auth_mode` from the same resolver the campaign endpoints
use, so it can never drift from the real decision. When per-user execution is
on but a precondition is missing, the resolver fails closed and the status
says so: `auth_mode: null` plus `interactive_blocked_code` carrying the same
code the endpoints would return.

## Execution flow

```
Cognito user → ECP request.user → IsStaffOrSuperuser
  → get_mautic_client(actor, INTERACTIVE)
        flag off                        → SERVICE_ACCOUNT
        flag on + active mapping + keys  → ASSERTED_USER
        flag on + anything missing       → raises (never a silent downgrade)
  → POST /api/ecp/bridge/campaigns/new
        Basic Auth:                 ECP service account   (required)
        X-ECP-Identity-Assertion:   RS256, ≤90s, single use (required)
        X-ECP-Correlation-Id:       request correlation (not a credential)
  → verify → consume jti → runAs(mapped Mautic user)
  → native campaign API: CorePermissions + createdBy/modifiedBy as that user
  → service token restored in a finally block
```

## Operation binding

Each assertion names the single operation it authorises, and each bridge route
accepts only its own:

```
claims: {iss, aud, sub, mautic_user_id, purpose: "interactive",
         operation: "campaign.create" | "campaign.update", iat, exp, jti}
```

Without this, an assertion minted for one route could be presented to another
inside its validity window — for example turning a create into an edit of an
arbitrary campaign the user may edit.

* **ECP** refuses to sign for an operation outside `ASSERTABLE_OPERATIONS`
  (`newsletter/mautic/operations.py`); `operation` has no default.
* **Mautic** compares the claim with the route's operation using
  `hash_equals`. A mismatch is a 401, checked *before* the jti is consumed, so
  a mis-routed assertion is not burned.
* The operation strings are a contract: `operations.py` and the
  `OPERATION_*` constants on `EcpBridgeCampaignApiController` must match.

Adding an operation means adding it on both sides, together with its route.

**Deploy order.** Mautic now rejects assertions without an `operation` claim,
and older ECP builds do not send one. Deploy the Mautic plugin and ECP
together, or keep `ECP_MAUTIC_PER_USER_EXECUTION_ENABLED` off until both are
updated. With the flag off no assertions are sent, so there is no impact.

## Permissions

Three layers, all required:

1. **ECP** — `IsStaffOrSuperuser` on the endpoint.
2. **ECP identity** — active mapping and configured signing, else a typed
   exception (below).
3. **Mautic native** — after the context switch, `campaign:campaigns:create`
   for create and `editown`/`editother` with entity ownership for update.
   Nothing here re-implements Mautic's permission model.

## Failure codes

Every condition has its own status and stable `code`; responses carry
`{"detail", "code"}` and never leak assertions, keys, credentials or provider
text.

| Condition | Status | `code` |
|---|---|---|
| No mapping | 409 | `mautic_user_not_connected` |
| Mapping disabled | 409 | `mautic_user_connection_inactive` |
| Not a Marketing Hub actor | 403 | `mautic_actor_required` |
| Mautic refused the user or its permissions | 403 | `mautic_permission_denied` |
| Signing not configured | 503 | `mautic_identity_not_configured` |
| Assertion could not be issued | 503 | `mautic_identity_assertion_failed` |
| Mapping validation (e.g. Mautic user taken) | 400 | `mautic_identity_error` + specific message |

## Audit flow

`MauticIdentityAuditLog` is append-only: written on every attempt, never
updated or deleted by application code, and exposed read-only.

Recorded: `ecp_user` (+ `ecp_user_label`, which survives user deletion),
`mautic_user_id`, `action`, `resource`, `resource_id`, `status`
(succeeded/failed/denied), `auth_mode`, `correlation_id`, `assertion_jti`,
`error_code`, `detail`, `created_at`.

Never recorded: assertions, signatures, keys, passwords, Cognito tokens. The
`detail` field holds an exception class name, not provider text.

Auditing never breaks an operation: a write failure is logged and swallowed.

`assertion_jti` names the single-use assertion that authorised the call, so an
audit row can be matched to one row in the Mautic-side replay table. It is an
identifier, never the assertion itself.

The same `correlation_id` is sent to Mautic, logged on both sides, and returned
in the `X-ECP-Correlation-Id` response header by both the Mautic bridge and the
ECP campaign endpoints — on refusals as well as successes — so one Marketing
Hub action can be traced from the browser through both systems. Inbound values
are untrusted: they are stripped to `[A-Za-z0-9_-]` and capped at 64
characters.

## Diagnostics

**ECP** — `GET …/settings/mautic-diagnostics/` gained an `identity` block:
`per_user_execution_enabled`, `signing_configured`, `key_id_configured`,
`issuer`, `audience`, `active_connections`, `current_user_connected`,
`mautic_identity` (as reported by the plugin), plus `status` and `warnings`
that merge into the top-level diagnostics warnings.

**Mautic** — `GET /api/ecp/capabilities` gained an `identity` block:
`publicKeyConfigured`, `keyIdConfigured`, `issuer`, `audience`,
`clockSkewSeconds`, `verifierActive`, `configurationError`, `replayStorage`
(availability + table name), and `ready`. Booleans and labels only — never the
key itself.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| 409 `mautic_user_not_connected` | No active mapping | Create one via `POST …/connections/` |
| 409 `mautic_user_connection_inactive` | Mapping disabled | `POST …/connections/{id}/activate/` |
| 503 `mautic_identity_not_configured` | ECP private key / key id missing | Set `ECP_MAUTIC_IDENTITY_*` |
| 401 from the bridge | Bad, expired or replayed assertion; clock skew; operation mismatch | Check `clockSkewSeconds`, that both sides share `kid`, issuer and audience, and that ECP and the plugin are on matching builds (operation binding) |
| 403 `mautic_permission_denied` | Mapped Mautic user lacks the campaign permission | Adjust that user's Mautic role |
| 503 at the bridge, `replayStorage.available=false` | Replay table missing | Install/reload the plugin schema so `ecp_identity_assertion_uses` exists |
| Attribution shows the service account | Flag off, or the request used a non-migrated path | Only campaign create/update are migrated |

Trace any single action with
`GET …/mautic-identity/audit/?correlation_id=<id>`.

## Migration

One migration: `newsletter/migrations/0009_mauticidentityauditlog.py`
(`CreateModel` only — no existing table is touched). Migrations are gitignored
in this development repository, so it is generated locally and not committed.

## Enabling it in a development environment

Order matters: the flag is the last step, because it fails closed.

1. **Key pair** — generate RSA 2048+ outside the repo. The private half goes to
   ECP as `ECP_MAUTIC_IDENTITY_PRIVATE_KEY` (PEM, literal `\n` accepted); the
   public half goes to Mautic as the `ecp_identity_public_key` parameter. Both
   sides must agree on `kid`, issuer and audience. No key material is
   committed, and the two halves are never in the same place.
2. **Replay table** — install the plugin schema so
   `ecp_identity_assertion_uses` exists. Until it does, the bridge refuses
   every assertion rather than accepting one it cannot mark as used.
3. **Verify Mautic first** — `GET /api/ecp/capabilities` must report
   `identity.ready: true` and `replayStorage.available: true`.
4. **Mappings** — connect each Marketing Hub user to their Mautic user id via
   `POST …/connections/`. Users with no mapping will be refused once the flag
   is on, so map before enabling.
5. **Flag** — set `ECP_MAUTIC_PER_USER_EXECUTION_ENABLED=true`. Confirm with
   `GET …/mautic-identity/status/`: `auth_mode` should read `asserted_user`.

Worth knowing: the flag and the signing settings are read from the
environment, so test suites that assert dormant behaviour pin them explicitly
rather than inheriting a developer's local values.

## Not in Phase 3

Automatic Mautic user provisioning, role synchronization, operations beyond
campaign create/update, browser SSO, frontend changes, key rotation tooling,
production keys or deployment.
