# Workspaces: reference

Hooks, events, account deletion, invitations through OAuth and the threat model for [workspaces](../README.md).

## Hooks and events

`beforeWorkspaceCreate(user, { name }, context)` can refuse a creation. `onWorkspaceEvent(event,
context)` receives, after the change has committed, `workspace.created`, `.renamed`,
`.deletion_scheduled`, `.restored` and `.deleted`; `member.invited`, `invitation.resent`,
`.revoked` and `.accepted`; `member.role_changed`, `.removed` and `.left`; `ownership.transferred`;
`workspace.switched`; and `access.denied` (with the `surface`, the public `code` and a host-only
`reason`). It is best-effort and informational: the repository's persisted audit row is the record.

## Deleting an account

The library never deletes a user: `IUserRepository` has no delete. A host that deletes or anonymises
a user row must remove that user's memberships first, or the rows stay behind, still count as
members of their workspaces, and a deleted owner keeps a workspace from ever being seen as
orphaned. Call `MembershipService.removeAllForUser(tenantId, userId, actorUserId, context)` before
the delete. `actorUserId` is the account itself, an administrator, or `null` for a job.

It removes every membership of the account, in every membership status and every workspace, with one
`member.removed` event per removal and the cached access of each dropped, so access ends at the next
request. Only the repository can find them all (`listForUser` lists active memberships of active
workspaces only), so it is one call on the membership port, `removeAllForUser`, which you implement
in one transaction together with the audit rows.

- **It refuses while the account is the only owner of an active or suspended workspace:** `409
auth.last_owner` with `details.workspaces` (`{ id, name, status }`, at most 100; `{ id }` alone for one the repository found during the write), and nothing is
  removed. Transfer ownership or schedule the workspace's deletion first.
- **A workspace pending deletion does not block.** No one can finalize a pending deletion before
  its grace period ends, so an owner who scheduled one would otherwise be unable to delete their own
  account for the whole period. Their membership there is removed with the rest, the workspace can no
  longer be restored (restoring is owner-only), and your finalize job deletes it when the grace period
  ends.
- **If a cache bump fails after the commit,** the call throws `MembershipBumpFailedError` with
  `removed` and `failed`. The removal is already committed, so calling it again removes nothing: drop
  the access of each entry of `failed` with `WorkspaceAccessService.invalidateMembership`, or wait out
  `membershipCacheTtlSeconds`.

## Accepting an invitation through OAuth, and MFA

An OAuth flow started with a workspace invitation vets the invitation against the provider's profile
before your `onOAuthLogin` hook runs, and completes it for the account that results. **When that
account has a second factor, the library does not complete the invitation:** the callback answers the
MFA challenge as it does for any OAuth sign-in, the invitation stays pending and unspent, and it is
not resumed after the challenge. The signed-in caller accepts it with `POST
workspaces/invitations/accept` and the same token, so a host whose members use MFA should send the
token again from its accept page after sign-in.

## Threat model

A workspace id is never trusted from the body, a header or a stored default; the guard resolves it
from the route and the membership from the repository. Non-members and nonexistent workspaces are
indistinguishable. A platform token has no implicit bypass. Memberships are cached for
`membershipCacheTtlSeconds` and read under version counters, so a stale value is never served after a
change the library made. The host's rate limiting on guarded routes is what bounds a caller probing
workspace ids.

## Paging in your repository

`listForUser`, `listForWorkspace` and `listSoleOwned` page by a keyset, and the port requires one rule
of every cursor a repository reads: a malformed cursor, or one issued for another query, restarts from
the first page and never widens the scope. The library exports the codec so an adapter does not write
its own:

```typescript
import {
  decodeWorkspaceCursor,
  encodeWorkspaceCursor,
  readWorkspacePosition,
  workspacePositionOf,
  workspaceQueryKey
} from '@bymax-one/nest-auth'

// The query names everything that scopes the listing, so a cursor never reads in another one.
const query = workspaceQueryKey('listForUser', tenantId, userId)

// Resume after the cursor's position, or from the start when it reads as none.
const resume = readWorkspacePosition(decodeWorkspaceCursor(cursor, query) ?? '')

// ... read limit + 1 rows after `resume`, in (createdAt, id) order ...
const nextCursor = hasMore
  ? encodeWorkspaceCursor(query, workspacePositionOf(last.createdAt, last.id))
  : null
```

- The scope of a listing comes from the query the store builds, never from the cursor. A cursor is a
  bookmark and not a signature: a well-formed position another instant names moves within the same scope
  and nowhere else.
- `decodeWorkspaceCursor` never throws. It reads as none a value that is not a string, one over 4096
  characters, anything but the canonical encoding, bytes that are not UTF-8, anything but a pair of two
  strings, a pair issued for another query, and an empty or ill-formed position.
- `encodeWorkspaceCursor` throws a `RangeError` rather than issue a cursor the next request could not
  follow: an empty or ill-formed position, or a cursor over 4096 characters, which only an id, a tenant or
  a key part over 128 code points can cause. Keep every id you issue to 128 code points of well-formed text.
- `workspaceQueryKey` is `JSON.stringify` of its parts, and is also fit for any key that must stay
  unambiguous, a lock name for example.
- `workspaces.roles.ownerRole` is checked at startup against `WORKSPACE_OWNER_ROLE_PATTERN`, because it is
  part of the key of `listSoleOwned`.
