import { HttpStatus, Inject, Injectable, Logger } from '@nestjs/common'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'
import type { ResolvedOptions } from '../config/resolved-options'
import { generateSecureToken, hmacSha256, sha256 } from '../crypto/secure-token'
import type { AcceptInvitationDto } from '../dto/accept-invitation.dto'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { AuthResult } from '../interfaces/auth-result.interface'
import type { IEmailProvider } from '../interfaces/email-provider.interface'
import type { IUserRepository } from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { assertNotBlocked } from '../utils/assert-not-blocked'
import { logSafe } from '../utils/log-safe'
import { maskEmail } from '../utils/mask-email'
import { normalizeEmail } from '../utils/normalize-email'
import { hasRole } from '../utils/roles.util'
import { sanitizeHeaders } from '../utils/sanitize-headers'

/**
 * Stored payload for a pending invitation, kept in Redis.
 * The raw token is never stored — only its SHA-256 hash is used as the key.
 */
interface StoredInvitation {
  /** Normalized (lowercased, trimmed) email address of the invitee. */
  email: string
  /** Role to assign upon acceptance. */
  role: string
  /** Tenant the invitee will join. */
  tenantId: string
  /** Internal ID of the user who sent the invitation. */
  inviterUserId: string
  /** ISO timestamp of when the invitation was created. */
  createdAt: string
}

/**
 * Narrows an unknown value to `StoredInvitation` at runtime.
 *
 * Used after `JSON.parse` to prevent injection of unexpected field values
 * (e.g. a tampered `role`) from a compromised or misconfigured Redis instance.
 */
function isStoredInvitation(value: unknown): value is StoredInvitation {
  // Stryker disable next-line ConditionalExpression: non-object JSON primitives have no string fields, so the downstream field guards reject them identically when the type clause is dropped
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  return (
    typeof v['email'] === 'string' &&
    // Stryker disable next-line ConditionalExpression: equivalent — a non-string role is refused downstream by `Object.hasOwn(hierarchy, role)` and by `hasRole`, which compares by identity, so no non-string value can reach an account. Kept as the contract this guard states.
    typeof v['role'] === 'string' &&
    // Stryker disable next-line ConditionalExpression: equivalent — a non-string tenantId is refused downstream by `inviter.tenantId === invitation.tenantId`, a strict comparison against a string that no non-string can satisfy. Kept for the same reason as the role clause.
    typeof v['tenantId'] === 'string' &&
    typeof v['inviterUserId'] === 'string' &&
    typeof v['createdAt'] === 'string'
  )
}

/**
 * Manages tenant invitation flows — creating and accepting invitations.
 *
 * @remarks
 * Invitation tokens are generated with `generateSecureToken(32)` (64 hex chars),
 * stored in Redis under `inv:{sha256(token)}` with a configured TTL, and consumed
 * atomically (single-use) via `AuthRedisService.getdel()` when accepted. The raw
 * token is never persisted server-side — only the SHA-256 hash is kept as the key.
 *
 * Role authorization is validated in `invite()` using `hasRole()` from
 * `roles.util.ts` — the inviter cannot invite a role higher than their own.
 *
 * @example
 * ```typescript
 * // Inviting a new member (inviter must hold a role >= 'member')
 * await invitationService.invite(inviterUserId, 'new@example.com', 'member', tenantId)
 *
 * // Accepting an invitation
 * await invitationService.acceptInvitation(dto, ip, userAgent, headers)
 * ```
 *
 * @layer Service
 */
/**
 * How many times a supersede re-derives its approval before giving up.
 *
 * The rank check and the index claim are separate round trips, so a concurrent invite for the
 * same address can move the record between them. Re-deriving is the right answer — the
 * contention is between two legitimate inviters — but an unbounded retry turns a hot address
 * into an unbounded loop, so the budget is small and exceeding it is refused.
 */
const SUPERSEDE_ATTEMPTS = 3

@Injectable()
export class InvitationService {
  private readonly logger = new Logger(InvitationService.name)

  constructor(
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Inject(BYMAX_AUTH_EMAIL_PROVIDER) private readonly emailProvider: IEmailProvider,
    @Inject(BYMAX_AUTH_HOOKS) private readonly hooks: IAuthHooks,
    private readonly redis: AuthRedisService,
    private readonly passwordService: PasswordService,
    private readonly sessionService: SessionService,
    private readonly tokenManager: TokenManagerService,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions
  ) {}

  // ---------------------------------------------------------------------------
  // invite()
  // ---------------------------------------------------------------------------

  /**
   * Creates an invitation for `email` to join `tenantId` with `role`.
   *
   * Authorization sequence:
   * 1. Validates that `role` exists in `roles.hierarchy`.
   * 2. Fetches the inviter and verifies that `inviter.role >= role` via `hasRole()`.
   * 3. Generates a 32-byte (64 hex char) secure token, stores `inv:{sha256(token)}`
   *    in Redis with the configured TTL, and emails the raw token to the invitee.
   *    The raw token is passed as `inviteToken` in `InviteData` — the `IEmailProvider`
   *    implementation is responsible for constructing the full accept URL.
   *
   * @param inviterUserId - Internal ID of the authenticated user sending the invite.
   * @param email - Email address to invite. Normalized to lowercase at this boundary.
   * @param role - Role to assign upon acceptance.
   * @param tenantId - Tenant the invitee will join.
   * @param tenantName - Optional display name for the tenant in the invitation email.
   *   Falls back to `tenantId` when not provided.
   * @throws `ForbiddenException` with `INSUFFICIENT_ROLE` when the role is unknown
   *   or the inviter lacks authority to issue the requested role.
   * @throws `AuthException` with `TOKEN_INVALID` when the inviter user is not found.
   */
  async invite(
    inviterUserId: string,
    email: string,
    role: string,
    tenantId: string,
    tenantName?: string
  ): Promise<void> {
    // Normalize at the service boundary to guard against callers bypassing DTO transforms.
    const normalizedEmail = normalizeEmail(email)

    const hierarchy = this.options.roles.hierarchy

    // Validate that the requested role exists in the configured hierarchy.
    if (!Object.hasOwn(hierarchy, role)) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE, HttpStatus.FORBIDDEN)
    }

    // Fetch the inviter to validate their role authorization.
    const inviter = await this.userRepo.findById(inviterUserId)
    if (!inviter) {
      // The JWT references a user that no longer exists — treat as an invalid token.
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    // The inviter must belong to the tenant they are inviting into. Without this the only
    // authorization is the role-hierarchy check below, which says nothing about *where* the
    // role is held: an ADMIN of tenant A could mint an invitation that provisions an ADMIN
    // account inside tenant B. The shipped controller sources `tenantId` from the caller's own
    // claims, which hides it — but this is a library whose service layer consumers call
    // directly, and the authorization contract belongs here rather than in one caller.
    if (inviter.tenantId !== tenantId) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE, HttpStatus.FORBIDDEN)
    }

    // The inviter must hold a role >= the role being invited.
    if (!hasRole(inviter.role, role, hierarchy)) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE, HttpStatus.FORBIDDEN)
    }

    // Generate a cryptographically secure single-use token (64 hex chars).
    const rawToken = generateSecureToken(32)
    const tokenHash = sha256(rawToken)
    const tokenKey = `inv:${tokenHash}`
    const ttl = this.options.invitations.tokenTtlSeconds

    const stored: StoredInvitation = {
      email: normalizedEmail,
      role,
      tenantId,
      inviterUserId,
      createdAt: new Date().toISOString()
    }

    // Re-inviting an address supersedes the previous invitation rather than adding a second
    // one. Two live tokens for one invitee is two chances for an intercepted link to be
    // redeemed, and revoking would only ever reach the newest — the older one would sit there
    // valid and unreferenced for the rest of its TTL.
    //
    // Superseding DESTROYS a pending invitation, which is the same end state `revokeInvitation`
    // produces — so it is held to the same bar. Without this, `hasRole(inviter.role, role)` was
    // the only authorisation, and it is a check about the role being REQUESTED, not the role of
    // the invitation being destroyed: any tenant member could `POST {email: bob, role: MEMBER}`
    // and delete a pending ADMIN invitation for bob, a capability the revoke route refuses them
    // and refuses even to confirm exists.
    //
    // The rank check and the claim must agree about WHICH invitation is being superseded. Two
    // separate round trips do not: an outranked caller could pass the check while the index was
    // momentarily empty, and then displace a higher-ranked invitation created in between. So
    // the check reports the hash it approved, and the claim only proceeds if the index still
    // holds exactly that — a compare-and-swap. Anything else means the record moved, and the
    // approval no longer describes what is there.
    //
    // The index is claimed FIRST, and atomically, because it is the serialization point: it is
    // the only handle the issuing side has on a record keyed by a token nobody here ever saw.
    // Writing the record first and the index second left two failures. A failed index write
    // published a token that stays redeemable for its whole TTL while `revokeInvitation` reads
    // an absent index and answers 204 — an operator told the withdrawal succeeded over an
    // invitation that is still live. And two concurrent invites for one address interleaved
    // into two live `inv:` records with the index naming only the newer, which is exactly the
    // "two live tokens for one invitee" this supersede exists to prevent.
    //
    // Claiming the index first inverts the failure: a crash before the record is written leaves
    // an index naming nothing, so the invitation is simply dead — the safe direction.
    const supersededHash = await this.supersedeApprovedInvitation(
      inviter,
      normalizedEmail,
      tenantId,
      tokenHash,
      ttl
    )
    if (supersededHash !== null) {
      await this.redis.del(`inv:${supersededHash}`)
    }
    await this.redis.set(tokenKey, JSON.stringify(stored), ttl)

    const displayTenantName = tenantName ?? tenantId
    const expiresAt = new Date(Date.now() + ttl * 1_000)

    // Send the invitation email. The raw token is passed as inviteToken —
    // the IEmailProvider implementation is responsible for constructing the full URL.
    // The raw token is NOT logged here.
    await this.emailProvider.sendInvitation(normalizedEmail, {
      inviterName: inviter.name,
      tenantName: displayTenantName,
      inviteToken: rawToken,
      expiresAt
    })
    this.logger.log(
      `invite: invitation created email=${maskEmail(normalizedEmail)} role=${role} tenantId=${logSafe(tenantId)} inviterUserId=${inviterUserId}`
    )
  }

  // ---------------------------------------------------------------------------
  // acceptInvitation()
  // ---------------------------------------------------------------------------

  /**
   * Accepts a pending invitation and creates the new user account.
   *
   * Steps:
   * 1. Atomically reads and deletes `inv:{sha256(dto.token)}` via `getdel()`.
   *    Missing key → `INVALID_INVITATION_TOKEN`. The atomic consumption prevents
   *    race conditions where two concurrent requests both read a valid token before
   *    either deletes it.
   * 2. Validates and parses the stored JSON — rejects malformed payloads.
   * 3. Re-validates the stored `role` against the configured hierarchy to prevent
   *    privilege escalation from a tampered Redis value.
   * 4. Verifies the invitee email is not already registered in the tenant.
   * 5. Hashes `dto.password` via `PasswordService`.
   * 6. Creates the user with `emailVerified: true` (invitation implies email ownership).
   * 7. Issues dashboard tokens.
   * 8. Calls `hooks.afterInvitationAccepted` if implemented.
   *
   * @param dto - Validated AcceptInvitationDto from the request body.
   * @param ip - Client IP address (for session audit and hooks).
   * @param userAgent - User-Agent string (for session audit and hooks).
   * @returns Full `AuthResult` with access + refresh tokens and the new user record.
   * @throws `AuthException` with `INVALID_INVITATION_TOKEN` if the token is missing or malformed.
   * @throws `AuthException` with `EMAIL_ALREADY_EXISTS` if the email is taken.
   */
  /**
   * Whether an account's status still permits it to act.
   *
   * Routed through `assertNotBlocked` rather than an inline status test: one definition of
   * "blocked", and an inline version would have to re-implement its case-insensitive
   * comparison — a second implementation is a second thing to drift.
   *
   * @param user - The account to judge.
   * @returns `true` when the status is not one of the configured blocked ones.
   */
  private inGoodStanding(user: { status: string }): boolean {
    try {
      assertNotBlocked(user.status, this.options.blockedStatuses)
      return true
    } catch {
      return false
    }
  }

  /**
   * The invitee index key: the one handle the issuing side has on a pending invitation.
   *
   * The email is hashed rather than stored in the clear so a dump of the keyspace does not
   * enumerate who a tenant has been inviting, which the record itself never exposes either.
   *
   * @param email - The normalized invitee address.
   * @param tenantId - The tenant the invitation was issued for.
   * @returns The namespaced-by-caller key.
   */
  private inviteeKey(email: string, tenantId: string): string {
    return `invidx:${tenantId}:${this.inviteeIdentifier(email)}`
  }

  /**
   * Derives the invitee-index identifier for an address: `hmac('{email}')`.
   *
   * HMAC rather than a bare digest because an address is low-entropy — a plain SHA-256 of one
   * is reversible by dictionary, and this key is the one handle anyone reading a keyspace dump
   * has on who a tenant has been inviting. The tenant is not in the preimage because it is
   * already a literal segment of the key.
   *
   * The preimage is pinned by `conformance/wire-contract.json` and shared byte-for-byte with
   * rust-auth, which writes the same index into the same Redis.
   *
   * @param email - The canonicalized address.
   * @returns Hex HMAC-SHA-256 identifier.
   */
  private inviteeIdentifier(email: string): string {
    return hmacSha256(`${email}`, this.options.hmacKey)
  }

  /**
   * Refuses a caller who may not destroy the invitation their new one would supersede.
   *
   * `create`'s own authorisation is `hasRole(inviter.role, requestedRole)` — a statement about
   * the role being granted, which says nothing about the role of the record being replaced.
   * `revokeInvitation` is deliberately strict about that second question, so reaching the same
   * end state through `create` must be too, or the strictness is decoration.
   *
   * An unparseable record is superseded without a check, exactly as `revokeInvitation` treats
   * it: it can no longer be accepted either, and leaving it behind would be worse.
   *
   * @param inviter - The authenticated caller, already known to be in the tenant.
   * @param email - The normalized invitee address.
   * @param tenantId - The tenant the invitation belongs to.
   * @throws {@link AuthException} `INSUFFICIENT_ROLE` when the caller is outranked by the
   *   pending invitation. Unlike the revoke route this cannot answer silently — the caller is
   *   asking to create something, and a silent success would report an invitation that does
   *   not exist.
   */
  private async assertMaySupersede(
    inviter: { role: string; status: string },
    email: string,
    tenantId: string
  ): Promise<string | null> {
    const tokenHash = await this.redis.get(this.inviteeKey(email, tenantId))
    if (tokenHash === null) return null
    const raw = await this.redis.get(`inv:${tokenHash}`)
    const pending = raw === null ? null : this.parseInvitation(raw)
    if (pending !== null && !this.mayWithdraw(inviter, pending)) {
      this.logger.warn(
        `create: refused email=${maskEmail(email)} tenantId=${logSafe(tenantId)} ` +
          `inviterRole=${logSafe(inviter.role)} — outranked by the pending invitation`
      )
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE, HttpStatus.FORBIDDEN)
    }
    return tokenHash
  }

  /**
   * Approves the supersede and claims the index in one agreed step, retrying if the record
   * moves underneath the approval.
   *
   * The rank check and the claim are separate round trips, so on their own they can disagree
   * about WHICH invitation is being superseded: an outranked caller could pass the check while
   * the index was momentarily empty and then displace a higher-ranked invitation created in
   * between. The claim is therefore a compare-and-swap against the hash the check approved —
   * anything else means the record moved and the approval no longer describes what is there.
   *
   * A displaced approval is re-derived rather than refused: the contention is between two
   * legitimate inviters, and one of them losing a race is not an authorisation failure. The
   * retry is bounded, because an unbounded one turns a hot address into an unbounded loop.
   *
   * @param inviter - The authenticated caller, already known to be in the tenant.
   * @param email - The normalized invitee address.
   * @param tenantId - The tenant the invitation belongs to.
   * @param tokenHash - The new invitation's token hash.
   * @param ttl - The invitation TTL, in seconds.
   * @returns The displaced token hash, or `null` when there was no pending invitation.
   * @throws {@link AuthException} `INSUFFICIENT_ROLE` when the caller is outranked, or when the
   *   index kept moving for the whole retry budget — the caller has not been shown to be
   *   allowed to destroy whatever is there now.
   */
  private async supersedeApprovedInvitation(
    inviter: { role: string; status: string },
    email: string,
    tenantId: string,
    tokenHash: string,
    ttl: number
  ): Promise<string | null> {
    for (let attempt = 0; attempt < SUPERSEDE_ATTEMPTS; attempt += 1) {
      const approved = await this.assertMaySupersede(inviter, email, tenantId)
      const claim = await this.claimInviteeIndex(email, tenantId, tokenHash, ttl, approved)
      if (claim.claimed) return approved
    }
    this.logger.warn(
      `create: refused email=${maskEmail(email)} tenantId=${logSafe(tenantId)} ` +
        `— the pending invitation kept changing under the rank check`
    )
    throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE, HttpStatus.FORBIDDEN)
  }

  /**
   * Atomically points the invitee index at `tokenHash`, answering with the hash it displaced.
   *
   * A compare-and-swap, not a plain write: the claim proceeds only when the index still holds
   * exactly what the rank check approved. Two concurrent invites for one address therefore
   * cannot both believe they superseded nothing — exactly one wins, and the loser is told the
   * record moved so it can re-derive its approval against what is actually there.
   *
   * @param email - The normalized invitee address.
   * @param tenantId - The tenant the invitation belongs to.
   * @param tokenHash - The new invitation's token hash.
   * @param ttl - The invitation TTL, in seconds.
   * @param expected - The hash the rank check approved, or `null` for "no pending invitation".
   * @returns Whether this call claimed the index.
   */
  private async claimInviteeIndex(
    email: string,
    tenantId: string,
    tokenHash: string,
    ttl: number,
    expected: string | null
  ): Promise<{ claimed: boolean }> {
    // `ARGV[3]` is the empty string for "the index must be absent", which is distinguishable
    // from any real hash because a hash is always 64 hex characters.
    const claimed = await this.redis.eval(
      `local old = redis.call('GET', KEYS[1])
       if (old or '') ~= ARGV[3] then return 0 end
       redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
       return 1`,
      [this.inviteeKey(email, tenantId)],
      [tokenHash, String(ttl), expected ?? '']
    )
    // Narrowed rather than compared straight to `1`: `eval` answers `unknown`, and a client
    // that surfaced the Lua integer as a string would read a successful claim as contention.
    return { claimed: typeof claimed === 'number' ? claimed === 1 : claimed === '1' }
  }

  // ---------------------------------------------------------------------------
  // revokeInvitation()
  // ---------------------------------------------------------------------------

  /**
   * Withdraws a pending invitation before it is accepted.
   *
   * An invitation is a credential: it provisions an account, at a role, inside a tenant,
   * to whoever holds the link. Until now the library could mint one and had no way to take
   * it back — a link sent to the wrong address, or sent by someone who has since left, stayed
   * redeemable for its whole TTL with nothing an operator could do about it. ASVS v5 §6.1.1
   * expects an administrative path to invalidate a credential that should no longer work.
   *
   * The revoker is held to the same bar as the issuer: they must belong to the tenant, be in
   * good standing, and out-rank the role the invitation grants. Anything looser would let a
   * member cancel an admin's invitations.
   *
   * Idempotent: revoking an invitation that never existed, already expired, or was already
   * accepted is not an error — the end state the caller asked for is the end state they get,
   * and reporting the difference would tell them whether an address has a pending invitation,
   * which is precisely what the index hashes the email to avoid disclosing.
   *
   * @param revokerUserId - Internal ID of the authenticated user withdrawing the invitation.
   * @param email - The invited address. Normalized at this boundary.
   * @param tenantId - The tenant the invitation was issued for.
   * @returns `true` when a pending invitation was removed, `false` when there was none.
   * @throws {@link AuthException} `TOKEN_INVALID` when the revoker no longer exists, or
   *   `INSUFFICIENT_ROLE` when they may not withdraw this invitation.
   */
  async revokeInvitation(revokerUserId: string, email: string, tenantId: string): Promise<boolean> {
    const normalizedEmail = normalizeEmail(email)

    const revoker = await this.userRepo.findById(revokerUserId)
    if (!revoker) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
    if (revoker.tenantId !== tenantId) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE, HttpStatus.FORBIDDEN)
    }
    // Standing is a fact about the CALLER, so refusing out loud describes nobody else — and it
    // is settled before any lookup, so a suspended account cannot use this door to ask
    // questions at all. The rank comparison below is the opposite kind of check, and is
    // answered the opposite way.
    if (!this.inGoodStanding(revoker)) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE, HttpStatus.FORBIDDEN)
    }

    const indexKey = this.inviteeKey(normalizedEmail, tenantId)
    const tokenHash = await this.redis.get(indexKey)
    if (tokenHash === null) return false

    // The role check reads the invitation itself rather than the request: the caller names an
    // address, not a role, so the only way to know what authority is being withdrawn is to
    // look. A record that no longer parses is withdrawn without a role check — it can no
    // longer be accepted either, and leaving it would be worse than removing it.
    const raw = await this.redis.get(`inv:${tokenHash}`)
    const invitation = raw === null ? null : this.parseInvitation(raw)

    // A revoker who may not withdraw THIS invitation is answered exactly as one who asked
    // about an address with no invitation at all. `INSUFFICIENT_ROLE` here was an oracle: the
    // caller names an address and nothing else, so a 403 said "there is a pending invitation
    // for this address, at a role above yours" while a 204 said "there is none" — letting any
    // member enumerate a tenant's pending invitations, and roughly at what authority. That is
    // precisely the disclosure the index hashes the address to prevent. The refusal is
    // recorded server-side, where an operator can see it and the prober cannot.
    if (invitation !== null && !this.mayWithdraw(revoker, invitation)) {
      this.logger.warn(
        `revokeInvitation: refused email=${maskEmail(normalizedEmail)} ` +
          `tenantId=${logSafe(tenantId)} revokerUserId=${revokerUserId} — outranked by the invitation`
      )
      return false
    }

    await this.redis.del(indexKey)
    const removed = await this.redis.del(`inv:${tokenHash}`)
    this.logger.log(
      `revokeInvitation: invitation withdrawn email=${maskEmail(normalizedEmail)} ` +
        `tenantId=${logSafe(tenantId)} revokerUserId=${revokerUserId}`
    )
    return removed
  }

  /**
   * Parses a stored invitation, answering `null` for anything that is not one.
   *
   * @param raw - The stored JSON.
   * @returns The validated record, or `null`.
   */
  private parseInvitation(raw: string): StoredInvitation | null {
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      // Deliberately swallowed and deliberately NOT an early return: an unparsed value stays
      // `undefined` and fails the guard below on the same line every other malformed record
      // fails on. An early return here would be a second spelling of the same answer, which no
      // test could tell apart from this one.
    }
    return isStoredInvitation(parsed) ? parsed : null
  }

  /**
   * Whether `revoker` out-ranks the role `invitation` grants.
   *
   * Standing is checked by the caller, before the invitation is looked up at all: the two
   * belong on opposite sides of the disclosure line, because this comparison depends on the
   * target and that one does not.
   *
   * @param revoker - The authenticated user, already known to be in good standing.
   * @param invitation - The pending record.
   * @returns `true` when the withdrawal is authorised.
   */
  private mayWithdraw(
    revoker: { role: string; status: string },
    invitation: StoredInvitation
  ): boolean {
    return hasRole(revoker.role, invitation.role, this.options.roles.hierarchy)
  }

  /**
   * Re-checks, at redemption time, everything that was true of the inviter when the link was
   * minted.
   *
   * An invitation is a delegation of authority, and authority is revocable. Validating it only
   * at creation means a 48-hour token carries whatever power its author had at the moment they
   * clicked send — surviving their suspension, their demotion, and their removal from the
   * tenant. The failure is answered as `INVALID_INVITATION_TOKEN` rather than as a role error:
   * the redeemer is not the one who lost authority, and telling them *why* would describe the
   * inviter's account status to someone who may be a stranger to it.
   *
   * @param invitation - The stored record, already shape-validated.
   * @throws {@link AuthException} `INVALID_INVITATION_TOKEN` when the inviter can no longer
   *   grant what the invitation grants.
   */
  private async assertInviterStillAuthorised(invitation: StoredInvitation): Promise<void> {
    const inviter = await this.userRepo.findById(invitation.inviterUserId)

    // One null test, not two. The good-standing check used to carry its own `inviter !== null`
    // and then the conjunction below repeated it — so neither could be removed without the
    // other still refusing, and no test could tell either apart from its twin.
    const stillAuthorised =
      inviter !== null &&
      this.inGoodStanding(inviter) &&
      inviter.tenantId === invitation.tenantId &&
      hasRole(inviter.role, invitation.role, this.options.roles.hierarchy)

    if (!stillAuthorised) {
      this.logger.warn(
        `acceptInvitation: the inviter can no longer grant this invitation ` +
          `inviterUserId=${invitation.inviterUserId} role=${invitation.role}`
      )
      throw new AuthException(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
    }
  }

  async acceptInvitation(
    dto: AcceptInvitationDto,
    ip: string,
    userAgent: string,
    headers: Record<string, string | string[] | undefined>
  ): Promise<AuthResult> {
    const tokenKey = `inv:${sha256(dto.token)}`

    // Atomically read and delete — single-use enforcement prevents race conditions.
    const raw = await this.redis.getdel(tokenKey)

    if (!raw) {
      throw new AuthException(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
    }

    // Validate JSON structure before trusting any field values.
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      // A record that exists but does not parse is corrupted storage, not an expired or
      // forged invitation — the caller cannot tell the two apart (both answer the same code)
      // and only this line does.
      this.logger.warn('acceptInvitation: stored invitation is not parseable JSON')
      throw new AuthException(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
    }

    if (!isStoredInvitation(parsed)) {
      throw new AuthException(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
    }

    const invitation = parsed

    // The record is already gone; drop the index that pointed at it so a later revoke does not
    // report success over an invitation that was accepted. Both carry the same TTL, so this is
    // tidiness rather than correctness — but a stale pointer is exactly the kind of thing an
    // operator reads as "still pending".
    await this.redis.del(this.inviteeKey(invitation.email, invitation.tenantId))

    // Re-validate role against the hierarchy to guard against Redis tampering.
    if (!Object.hasOwn(this.options.roles.hierarchy, invitation.role)) {
      throw new AuthException(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
    }

    // …and re-validate the INVITER, whose authority is what the invitation rests on. It was
    // checked when the link was minted and never again, so for the token's whole lifetime the
    // invitation outlived the person behind it: an admin could send one, be banned and stripped
    // of their role, and the invitee would still arrive as an admin of that tenant with a live
    // session. That is a clean way to keep a foothold across the account kill switch, which
    // makes the switch advisory. Re-reading closes it: the inviter must still exist, still be
    // in good standing, still belong to this tenant, and still out-rank the role being granted.
    await this.assertInviterStillAuthorised(invitation)

    // Guard against duplicate registrations within the same tenant.
    const existing = await this.userRepo.findByEmail(invitation.email, invitation.tenantId)
    if (existing) {
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS)
    }

    await this.passwordService.assertNotCompromised(dto.password)
    const passwordHash = await this.passwordService.hash(dto.password)

    const authUser = await this.userRepo.create({
      email: invitation.email,
      name: dto.name,
      passwordHash,
      role: invitation.role,
      tenantId: invitation.tenantId,
      // Invitation implies the invitee controls the email address.
      emailVerified: true
    })

    // Strip credential fields before token issuance — prevents passwordHash / mfaSecret
    // from flowing into the AuthResult.user field that is serialized in the response.
    // Matches the pattern used in auth.service.ts and oauth.service.ts.
    const { passwordHash: _ph, mfaSecret: _ms, mfaRecoveryCodes: _mrc, ...safeUser } = authUser

    const result = await this.tokenManager.issueTokens(safeUser, ip, userAgent)

    // Create a tracked session if session management is enabled.
    // Omitting this would leave the invitation-created account invisible in
    // GET /sessions and unrevokable via DELETE /sessions/:id.
    if (this.options.sessions.enabled) {
      await this.sessionService.createSession(safeUser.id, result.rawRefreshToken, ip, userAgent)
    }

    this.logger.log(
      `acceptInvitation: invitation accepted userId=${safeUser.id} tenantId=${invitation.tenantId} role=${invitation.role}`
    )

    // afterInvitationAccepted — fire-and-forget; errors must not propagate.
    if (this.hooks?.afterInvitationAccepted) {
      void Promise.resolve(
        this.hooks.afterInvitationAccepted(safeUser, {
          ip,
          userAgent,
          sanitizedHeaders: sanitizeHeaders(headers)
        })
      ).catch((err: unknown) => {
        this.logger.error('afterInvitationAccepted hook threw', err)
      })
    }

    return result
  }
}
