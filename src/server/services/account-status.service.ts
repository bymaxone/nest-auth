/**
 * @fileoverview Account lifecycle gate shared by the status guard and the token verifier.
 *
 * @layer Service
 */

import { Inject, Injectable, Optional } from '@nestjs/common'

import {
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { IPlatformUserRepository } from '../interfaces/platform-user-repository.interface'
import type { IUserRepository } from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { assertNotBlocked } from '../utils/assert-not-blocked'

/**
 * The two cache keys naming one dashboard account.
 *
 * The single statement of this format, and deliberately **not** exported. Anything that needs one
 * of these entries gone — library code included — goes through
 * {@link AccountStatusService.invalidate} rather than naming the key itself. A second statement of
 * a key format drifts out of agreement silently: the delete stops matching, nothing raises, and
 * the entry simply survives to its TTL.
 *
 * @param ref - The account to name. The tenant is required: a repository id is unique only WITHIN
 *   a tenant, so a key built from a bare id can answer for a colliding id elsewhere.
 * @returns The status key and the email-verified key for that account.
 */
function cacheKeysFor(ref: { readonly userId: string; readonly tenantId: string }): {
  readonly statusKey: string
  readonly verifiedKey: string
} {
  // Each half is percent-encoded before it is joined by `:`, so a tenant or subject that itself
  // contains a `:` cannot shift the boundary and collide with another pair (`('a:b','c')` and
  // `('a','b:c')` would otherwise both key `a:b:c`).
  const scope = `${encodeURIComponent(ref.tenantId)}:${encodeURIComponent(ref.userId)}`
  return { statusKey: `us:${scope}`, verifiedKey: `uev:${scope}` }
}

/**
 * Resolves an account's current lifecycle state and refuses the ones a deployment blocks.
 *
 * The answer a token carries is a snapshot taken at issuance: `DashboardJwtPayload.status` says
 * what the account was when it signed in, not what it is now. Anything that outlives a single
 * request — an access token's whole lifetime, a stream held open for hours — therefore has to ask
 * again, which is what this service exists to do.
 *
 * It reads through a Redis cache (`us:{tenantId}:{userId}`, and `uev:` for the verified flag)
 * rather than the repository, so asking on every request or on every reconnect costs one `get`
 * rather than a database round trip. A miss resolves both facts from a single tenant-scoped read
 * and writes both back for `userStatusCacheTtlSeconds`.
 *
 * Both {@link UserStatusGuard} and {@link AuthTokenVerifierService} delegate here rather than
 * carrying a copy: the cache key shape, the miss path and the order of the two refusals are one
 * rule, and a second implementation of it is how the two drift apart.
 *
 * @layer Service
 */
@Injectable()
export class AccountStatusService {
  /**
   * @param redis - The auth module's Redis service, holding the status and verified caches.
   * @param userRepo - The consumer's dashboard user repository, read on a cache miss.
   * @param options - Resolved module options, for the cache TTL and the blocked-status set.
   * @param platformUserRepo - The consumer's platform administrator repository. Absent unless
   *   `controllers.platform` is on, which is also the only configuration that can mint a
   *   platform token — so its absence is never a gap, and is refused rather than skipped.
   */
  constructor(
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Optional()
    @Inject(BYMAX_AUTH_PLATFORM_USER_REPOSITORY)
    private readonly platformUserRepo?: IPlatformUserRepository
  ) {}

  /**
   * Drops the cached status and email-verified flag for one account, so the next check re-reads
   * them from the repository.
   *
   * **Call this whenever you change an account's status outside this library.** A host suspending
   * a user through its own admin surface leaves this cache holding `active` until it expires, and
   * the suspended user keeps reaching protected routes for up to `userStatusCacheTtlSeconds`. This
   * is the supported way to close that window; reaching into the key prefix is not, because the
   * format is this library's to change and a delete that stops matching fails silently.
   *
   * Both keys go, not only the one a given caller cares about. They are written together and
   * dropping the other costs one repository read on the next request — a smaller price than an API
   * where the caller has to know which of two entries their change invalidated.
   *
   * Idempotent: deleting an absent key is not an error, so a caller need not know whether the
   * account was ever cached.
   *
   * **What it does not guarantee.** A request already in flight can repopulate the entry. The read
   * path fills the cache in two steps — resolve from the repository, then write — so a request
   * that resolved `active` just before your update lands will write `active` afterwards, with a
   * full TTL, however promptly you call this. The window is one repository read wide, not one TTL,
   * which is the whole improvement over letting the entry expire; it is not zero. **Order your own
   * writes accordingly: persist the status change first, then invalidate** — that way any request
   * whose repository read starts after your write already sees the new value, and only the
   * genuinely concurrent ones can lose the race.
   *
   * Closing it entirely needs the fill to be conditional on nothing having invalidated in between —
   * a per-account generation the write compares against — which is a mechanism this service does
   * not have. Tracked rather than implied.
   *
   * @param ref - The account whose cached facts are now stale. Both fields must be non-empty.
   * @throws {TypeError} When either id is empty or blank. Refused rather than attempted: an empty
   *   tenant builds `us::{userId}`, which names no entry any read ever wrote, so the delete would
   *   remove nothing and resolve normally — the caller's admin surface reports the suspension
   *   applied while the cached `active` survives its full TTL. That is the exact silent failure
   *   this method exists to eliminate, and an unset resolver value or a `undefined` coerced by a
   *   JavaScript host is how it arrives. A caller error, so not an `AuthException`.
   */
  async invalidate(ref: { readonly userId: string; readonly tenantId: string }): Promise<void> {
    if (ref.userId.trim() === '' || ref.tenantId.trim() === '') {
      throw new TypeError('invalidate: userId and tenantId must both be non-empty')
    }

    const { statusKey, verifiedKey } = cacheKeysFor(ref)
    // The verified flag goes FIRST. If the second delete fails — a blip, a failover — the caller
    // sees the rejection either way, but the entry left behind should be the one whose staleness
    // merely costs a repository read. A stale `uev` of `0` locks a just-verified account out of
    // every protected route until it expires, and `verifyEmail` reaches here after the OTP is
    // spent and the flag is committed, so there is nothing for the user to retry.
    await this.redis.del(verifiedKey)
    await this.redis.del(statusKey)
  }

  /**
   * Refuses a dashboard account that is blocked, deleted, or unverified where verification gates
   * API access.
   *
   * @param ref - The account to resolve. The tenant is required, not optional: a repository id is
   *   unique only WITHIN a tenant, so a status cached or read under a bare id could answer for a
   *   colliding id in another tenant.
   * @throws {@link AuthException} with `TOKEN_INVALID` when no such account exists, the matching
   *   `ACCOUNT_*` code when the status is blocked, or `EMAIL_NOT_VERIFIED` when verification is
   *   required and the address is not verified.
   */
  async assertDashboardAccountUsable(ref: {
    readonly userId: string
    readonly tenantId: string
  }): Promise<void> {
    const { userId, tenantId } = ref
    const { statusKey, verifiedKey } = cacheKeysFor(ref)
    const cacheTtl = this.options.userStatusCacheTtlSeconds
    const requireVerified = this.options.emailVerification.required

    let status = await this.redis.get(statusKey)
    // Only consulted when verification is enforced; left null otherwise so the cost is a single
    // `get` for the common case.
    let verified = requireVerified ? await this.redis.get(verifiedKey) : null

    if (status === null || (requireVerified && verified === null)) {
      // A miss on either fact resolves both from one repository read, scoped to the tenant.
      const userRecord = await this.userRepo.findById({ id: userId, tenantId })
      if (!userRecord) {
        // The account is gone; the token outlived it.
        throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
      }
      status = userRecord.status
      await this.redis.set(statusKey, status, cacheTtl)
      if (requireVerified) {
        verified = userRecord.emailVerified ? '1' : '0'
        await this.redis.set(verifiedKey, verified, cacheTtl)
      }
    }

    // Passed as stored, not normalized here: `assertNotBlocked` canonicalizes both sides itself,
    // so folding the case first does the same work twice and puts the case rule in two places.
    assertNotBlocked(status, this.options.blockedStatuses)

    // Email verification is a gate on API access, not only on `login`. Registration mints a
    // session before the address is verified; without this check that session reaches every
    // protected surface while `emailVerified` is still false. A blocked status is refused first,
    // so a banned account is told it is banned rather than that it must verify.
    if (requireVerified && verified === '0') {
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED)
    }
  }

  /**
   * Refuses a platform administrator whose account is blocked or gone.
   *
   * Uncached, unlike the dashboard side. The platform repository exposes `findById(id)` with no
   * tenant to scope a cache key by, and the population is small enough that a read per call is
   * cheaper than a keyspace whose entries no flow invalidates.
   *
   * There is no email-verification arm: `emailVerification.required` gates tenant registration,
   * and a platform administrator is provisioned rather than self-registered.
   *
   * @param userId - The administrator's identifier, the token's `sub`.
   * @throws {@link AuthException} with `TOKEN_INVALID` when no platform repository is registered
   *   or no such administrator exists, or the matching `ACCOUNT_*` code when the status is
   *   blocked.
   */
  async assertPlatformAccountUsable(userId: string): Promise<void> {
    // Refused rather than skipped. A deployment without `controllers.platform` registers no
    // repository AND mints no platform token, so this branch answers a token that cannot have
    // been issued here — which is exactly the case that must not be waved through. Skipping the
    // check because the collaborator is missing is how a gate fails open.
    if (!this.platformUserRepo) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    const admin = await this.platformUserRepo.findById(userId)
    if (!admin) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    assertNotBlocked(admin.status, this.options.blockedStatuses)
  }
}
