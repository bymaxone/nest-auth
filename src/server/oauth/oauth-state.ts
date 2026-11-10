/**
 * @fileoverview The record an OAuth flow keeps in Redis between its two halves, and the check that
 * a value read back is one.
 *
 * @layer OAuth
 */

/** A sha256 digest as lowercase hexadecimal. */
const SHA256_HEX = /^[0-9a-f]{64}$/

/**
 * Stored payload for an OAuth state entry in Redis.
 * Keyed under `os:{sha256(state)}` — the raw state is never stored server-side.
 */
export interface StoredOAuthState {
  /**
   * The provider this state was minted for, compared against the provider named by the
   * callback path before the record is used.
   *
   * RFC 9700 §2.1/§4.4 makes mix-up defence REQUIRED for a client that talks to more than one
   * authorization server. Without this field the callback resolves the provider from its own
   * URL and then consumes any structurally valid state, so an attacker able to steer an honest
   * provider's callback to a hostile provider's path receives both the `code` and the PKCE
   * `code_verifier` — enough to redeem the code at the honest provider. PKCE does not help:
   * the verifier travels with the code by design.
   *
   * Only Google ships in-tree today, so this is defence-in-depth. It is stored anyway because
   * the record is a shared structure and adding a field costs less now than after a second
   * provider lands. Held byte-compatible with rust-auth.
   */
  provider: string
  /** Tenant identifier passed by the caller when initiating the flow. */
  tenantId: string
  /**
   * PKCE `code_verifier` (RFC 7636), held server-side for the lifetime of the
   * authorization flow and forwarded to the provider's token endpoint on
   * callback.
   *
   * Required, deliberately. `getAuthorizationUrl` writes one on every flow regardless of
   * provider, so a record without it is corrupt or forged — and treating it as "this flow
   * had no PKCE" would hand an attacker a downgrade: present a state record with the field
   * stripped and the exchange proceeds with no proof the caller started the flow.
   * `rust-auth` types the field as a plain `String`, so a record missing it fails to
   * deserialize there; refusing it here keeps the shared record readable by exactly one rule.
   */
  codeVerifier: string
  /**
   * The sha256 of the workspace invitation token the flow was started with, when it was. Only the
   * hash is stored, so the raw token never reaches Redis. Optional on the wire; a record that
   * carries it as anything but 64 hex characters is corrupt.
   */
  workspaceInvitation?: string
}

/** Narrows an unknown value to `StoredOAuthState` after `JSON.parse`. */
export function isStoredOAuthState(value: unknown): value is StoredOAuthState {
  // Stryker disable next-line ConditionalExpression: non-object JSON values also fail the `typeof parsed['tenantId'] !== 'string'` check below, so dropping the type guard yields the same false
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  // Required, like `codeVerifier` and for the same reason: a record without it is corrupt or
  // forged, and accepting one would restore exactly the unbound state the field exists to
  // prevent. rust-auth types it as a plain `String`, so a record missing it fails to
  // deserialize there too.
  if (typeof v['provider'] !== 'string') return false
  if (typeof v['tenantId'] !== 'string') return false
  if (typeof v['codeVerifier'] !== 'string') return false
  const invitation = v['workspaceInvitation']
  return invitation === undefined || (typeof invitation === 'string' && SHA256_HEX.test(invitation))
}
