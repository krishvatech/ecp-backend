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
| GET | `…/mautic-identity/status/` | Connection state of the calling user |
| GET | `…/mautic-identity/connections/` | List all mappings (`is_active`, `ecp_user_id`, paging) |
| POST | `…/mautic-identity/connections/` | Create or refresh a mapping |
| GET | `…/mautic-identity/connections/{id}/` | One mapping |
| POST | `…/mautic-identity/connections/{id}/activate/` | Re-enable |
| POST | `…/mautic-identity/connections/{id}/deactivate/` | Disable (optional `reason`) |
| GET | `…/mautic-identity/audit/` | Query the audit trail |

Prefix: `/api/newsletter/admin/settings/`.

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

The same `correlation_id` is sent to Mautic, logged on both sides, and echoed
back in the `X-ECP-Correlation-Id` response header, so one Marketing Hub action
can be traced end to end. Inbound values are untrusted: they are stripped to
`[A-Za-z0-9_-]` and capped at 64 characters.

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
| 401 from the bridge | Bad, expired or replayed assertion; clock skew | Check `clockSkewSeconds`, and that both sides share `kid`, issuer and audience |
| 403 `mautic_permission_denied` | Mapped Mautic user lacks the campaign permission | Adjust that user's Mautic role |
| 503 at the bridge, `replayStorage.available=false` | Replay table missing | Install/reload the plugin schema so `ecp_identity_assertion_uses` exists |
| Attribution shows the service account | Flag off, or the request used a non-migrated path | Only campaign create/update are migrated |

Trace any single action with
`GET …/mautic-identity/audit/?correlation_id=<id>`.

## Migration

One migration: `newsletter/migrations/0009_mauticidentityauditlog.py`
(`CreateModel` only — no existing table is touched). Migrations are gitignored
in this development repository, so it is generated locally and not committed.

## Not in Phase 3

Automatic Mautic user provisioning, role synchronization, operations beyond
campaign create/update, browser SSO, frontend changes, key rotation tooling,
production keys or deployment.
