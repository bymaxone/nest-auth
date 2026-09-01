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
   * The two cache keys naming one dashboard account.
   *
   * The single statement of this format. Everything that reads, writes or drops these entries goes
   * through here — including {@link AuthService}, which used to hand-build the `uev:` key inline
   * and could therefore drift out of agreement with the code that wrote it, silently: the delete
   * would simply stop matching and a just-verified account would keep a stale `0` until the entry
   * expired. Nothing failed, on either side.
   *
   * Static because it is a pure derivation and callers occasionally want the names without an
   * instance — a test asserting reader and writer agree, most usefully.
   *
   * @param ref - The account to name. The tenant is required: a repository id is unique only
   *   WITHIN a tenant, so a key built from a bare id can answer for a colliding id elsewhere.
   * @returns The status key and the email-verified key for that account.
   */
  static cacheKeys(ref: { readonly userId: string; readonly tenantId: string }): {
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
   * @param ref - The account whose cached facts are now stale.
   */
  async invalidate(ref: { readonly userId: string; readonly tenantId: string }): Promise<void> {
    const { statusKey, verifiedKey } = AccountStatusService.cacheKeys(ref)
    await this.redis.del(statusKey)
    await this.redis.del(verifiedKey)
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
    const { statusKey, verifiedKey } = AccountStatusService.cacheKeys(ref)
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
