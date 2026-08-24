# SOAR Human Approval Contract and Runtime Acceptance

## Canonical model

The API request command and resulting workflow status are separate domains:

| Domain | Values |
| --- | --- |
| `ApprovalDecision` | `APPROVE`, `REJECT` |
| `ApprovalStatus` | `PENDING`, `APPROVED`, `REJECTED`, `EXPIRED`, `CANCELLED` |

`APPROVED` and `REJECTED` are never accepted as request decisions. The server is strict: case changes, surrounding whitespace, nulls, booleans, numbers, arrays, objects, unknown fields, missing reason, and a missing or stale version are rejected.

```json
{
  "decision": "APPROVE",
  "reason": "Validated by SOC analyst",
  "version": 4
}
```

An accepted command returns the resulting `ApprovalStatus`, the complete decision history, and the incremented optimistic `version`.

## State diagram

```text
PENDING --APPROVE quorum reached--> APPROVED --> dependent protected action READY
PENDING --APPROVE quorum pending--> PENDING  --> workflow remains waiting
PENDING --REJECT-----------------> REJECTED --> approval node FAILED; protected action cancelled
PENDING --expiry-----------------> EXPIRED  --> approval node FAILED; protected action cancelled
```

PostgreSQL locks the approval row, compares the supplied version, records the decision, advances the approval node and execution DAG, and appends the immutable tenant audit entry in one transaction. The action ledger uses `execution_id|node_id|action_type` as its idempotency key. A worker restart after approval claims the durable dependent action without recreating it.

## Authorization and tenant controls

- The endpoint requires `soar.actions.approve` in backend authorization.
- Tenant membership is checked independently of frontend visibility.
- Approval lookup and mutation are tenant-scoped.
- The execution initiator cannot approve their own action.
- Completed, expired, duplicate, stale-version, permission-denied, unauthenticated, and cross-tenant attempts are rejected and recorded in audit or security metrics.
- The worker has no endpoint that bypasses the approval node transition.

## Audit fields

Successful decisions record actor and tenant identity, approval request, playbook run, approval action node, command, previous and new statuses, reason, timestamp, correlation/request IDs, optimistic version, and bounded client/source metadata. Connector secrets and action payloads are not copied into the approval audit record.

## Terminology

| Meaning | RU | KK | EN |
| --- | --- | --- | --- |
| Approve command | Подтвердить | Мақұлдау | Approve |
| Reject command | Отклонить | Қабылдамау | Reject |
| Approved status | Подтверждено | Мақұлданды | Approved |
| Rejected status | Отклонено | Қабылданбады | Rejected |

Localized labels are display values only and never become API payload values.

## Test and runtime acceptance

Run the backend contract, race, frontend, and Compose gates documented in the repository. Runtime acceptance requires two different playbook runs with a `HUMAN_APPROVAL` node followed by a protected action:

1. Submit `APPROVE` with the current version and verify response `APPROVED`, version increment, one successful action ledger row, verification status, workflow completion, audit entry, UI timeline, and `soar_approval_approve_total`.
2. Submit `REJECT` with the current version and a reason; verify response `REJECTED`, no action ledger row, failed/reject branch, audit entry, UI timeline, and `soar_approval_reject_total`.
3. Repeat and race commands with the same version; verify one winner and controlled 409 conflicts.
4. Repeat with no token, a role without `soar.actions.approve`, and a foreign tenant; verify 401/403 and denial audit/metrics.
5. Restart the SOAR worker after `APPROVED` but before it claims the dependent action; verify one durable action execution.

This checklist is limited to server-side SOAR acceptance. It does not authorize endpoint agent or Sysmon rollout.
