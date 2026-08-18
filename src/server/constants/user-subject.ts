/**
 * The subject every user-derived Redis key is HMACed over.
 *
 * One definition rather than a copy per key family, and a copy that drifts is a key that silently
 * stops matching the one rust-auth derives from the same contract. It started as the MFA subject
 * and now backs every key that names an account: the five MFA store keys, the three MFA failure
 * counters, the recent-authentication marker, the session index and the token epoch.
 *
 * @layer Constants
 */

/**
 * Builds the tenant-scoped subject for a user-derived Redis key.
 *
 * The tenant is part of the dashboard arm because the library may not assume the consumer's user
 * ids are unique ACROSS tenants — `findById` takes a tenant precisely because they may not be, and
 * a host that numbers users per tenant gives every tenant a user `1`. Keyed on `{plane}:{userId}`
 * alone, two tenants' accounts shared every MFA store key and every MFA failure counter; the
 * counters were the worst, costing a credential-free cross-tenant lockout rather than a mere
 * collision.
 *
 * The derivation is driven by the **plane**, not by whether a tenant was supplied: the platform
 * arm carries no tenant segment because its admins are cross-tenant and have none, so a caller that
 * passes one on the platform plane cannot move the preimage off `platform:{userId}` — the shape is
 * half of a byte-for-byte agreement with rust-auth.
 *
 * **Supplying the dashboard tenant is the CALLER's obligation, and this function does not check
 * it.** It once could: every dashboard caller was an MFA flow behind `assertPlaneTenant`. That is
 * no longer true — the session index, the token epoch and the revocation check derive from here
 * too, and none of them passes through that guard. An absent tenant interpolates as the literal
 * text `undefined` and a blank one as nothing at all, producing `dashboard:9:undefined:{userId}` or
 * `dashboard:0::{userId}`: keyspaces belonging to no tenant, which nothing writes and no revocation
 * sweeps. Each caller refuses that shape on its own terms before reaching here.
 *
 * The length prefix keeps those two degenerate subjects distinct from each other and from every
 * real tenant's — no tenant has a 9-byte id spelled `undefined` unless it literally is one — so
 * they stay diagnosable rather than merging into one anonymous keyspace. That is a consolation,
 * not a licence: a caller reaching here without a tenant still names keys nobody sweeps.
 *
 * @param plane - The identity plane the subject belongs to.
 * @param userId - The account the key belongs to.
 * @param tenantId - The tenant the dashboard account belongs to; ignored on the platform plane.
 *   MUST be a non-empty string on the dashboard plane — see above.
 * @returns The subject string every user-derived key HMACs over.
 */
export function userSubject(
  plane: 'dashboard' | 'platform',
  userId: string,
  tenantId: string | undefined
): string {
  // The platform arm has ONE component after the plane, so there is nothing to disambiguate.
  if (plane === 'platform') return `platform:${userId}`

  // The dashboard arm has two, and a bare `:` between them is not injective over the identifiers
  // this library accepts. `tenant-id-charset.spec.ts` deliberately admits `acme.eu-west-1:prod`,
  // and `assertSubject` documents composite `tenant:user` subjects as a supported shape — so
  //
  //     tenantId 'acme:prod' + userId 'u1'   →  dashboard:acme:prod:u1
  //     tenantId 'acme'      + userId 'prod:u1' →  dashboard:acme:prod:u1
  //
  // collide, and with them every key derived from this preimage: the session index, the token
  // epoch, the MFA store keys, the MFA failure counters, the recent-authentication marker and the
  // recovery-code single-use claim. Two unrelated tenants would share all of them — which is the
  // cross-tenant revocation this whole change exists to remove, reintroduced through the
  // delimiter, and it also lets one tenant spend another's recovery code.
  //
  // The length prefix makes the split unambiguous: a reader knows exactly how many bytes the
  // tenant occupies, so no other (tenant, user) pair can produce the same string. No identifier
  // is rejected, which matters because the charset is deliberately permissive.
  //
  // BYTES, not `String.length`. JavaScript counts UTF-16 code units and Rust counts UTF-8 bytes,
  // so `'açaí'` is 4 by one measure and 6 by the other. This preimage is byte-shared with
  // `@bymax-one/rust-auth`; using `.length` would agree for ASCII and silently derive different
  // keys the first time a tenant id carried an accent.
  // `String(tenantId)`, not `tenantId ?? ''`: the length must measure exactly what the template
  // interpolates. Both render `undefined` as the nine-character text `undefined`, so the prefix
  // stays truthful even in that degenerate case — and it is one expression rather than a branch
  // no legitimate caller can reach, which would be an untestable line and a mutation survivor.
  // Reaching here without a tenant is a caller that skipped its boundary guard; the subject it
  // gets is still unambiguous, which is all this function owes it.
  const tenant = String(tenantId)
  return `dashboard:${Buffer.byteLength(tenant, 'utf8')}:${tenant}:${userId}`
}
