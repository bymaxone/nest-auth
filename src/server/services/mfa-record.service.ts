/**
 * @fileoverview The MFA record's moving parts: the serialized read-modify-write every transition
 * goes through, the single-use claim on a recovery code, TOTP anti-replay, the re-encryption of a
 * secret under the current key, and the account read behind the MFA flows.
 *
 * @layer Service
 */

import { randomBytes } from 'node:crypto'

import { Inject, Injectable, Logger, Optional } from '@nestjs/common'

import {
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { userSubject } from '../constants/user-subject'
import { hmacSha256 } from '../crypto/secure-token'
import { MAX_VERIFY_WINDOW, TOTP_STEP_SECONDS, verifyTotp } from '../crypto/totp'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type {
  AuthPlatformUser,
  IPlatformUserRepository
} from '../interfaces/platform-user-repository.interface'
import type { AuthUser, IUserRepository } from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { assertNotBlocked } from '../utils/assert-not-blocked'
import { describeChannelStatus } from '../utils/describe-error'
import { assertDashboardTenant } from '../utils/mfa-plane-tenant'
import { encryptMfaSecret, holdsSecret, type MfaSecretKeys } from '../utils/mfa-secret-cipher'

/**
 * TTL in seconds for the single-use claim on a recovery code (5 minutes).
 *
 * The claim serializes concurrent challenges presenting the same code; it is not the durable
 * record of consumption, which is the repository write that removes the code from the account.
 * Outliving that write by much would turn a failed write into a code the user can no longer
 * use but can still see in their list — so the marker is deliberately far shorter than the
 * code's real lifetime, and long enough that no plausible request pair slips past it.
 */
const RECOVERY_CODE_CLAIM_TTL_SECONDS = 300

/**
 * TTL in seconds for the TOTP anti-replay marker, derived from the drift window in force.
 *
 * The marker has to outlive every code the verifier would still accept, or a captured code
 * becomes replayable in the gap. A code used at step `S` may be the one minted for step
 * `S + w`, and that code stays acceptable until the end of step `S + 2w` — a span of
 * `(2w + 1)` steps measured from the start of `S`, which is exactly `(2w + 1) * 30` seconds.
 *
 * A fixed 90 seconds is right only for the default window of 1: a larger configured window
 * (`totpWindow: 2` accepts codes for 150 s) would outlive the marker and leave the last 60 s
 * replayable.
 *
 * `window` goes through the same clamp the verifier applies, so the marker is sized against
 * the window actually in force rather than the one configured. `rust-auth` derives it with
 * the identical formula.
 *
 * @param window - The configured drift window, in 30-second steps either side of now.
 * @returns The marker's TTL in seconds.
 */
function totpAntiReplayTtlSeconds(window: number): number {
  const effective = Math.min(Math.max(window, 0), MAX_VERIFY_WINDOW)
  return (2 * effective + 1) * TOTP_STEP_SECONDS
}

/**
 * The three fields every MFA transition rewrites together.
 *
 * `mfaSecret` and `mfaRecoveryCodes` widen to `undefined` as well as `null` because the two
 * planes' record types differ there — the dashboard user nulls them, the platform admin leaves
 * them absent — and one transition point has to satisfy both.
 */
export interface MfaRecordUpdate {
  mfaEnabled: boolean
  mfaSecret: string | null | undefined
  mfaRecoveryCodes: string[] | null | undefined
}

/**
 * TTL in seconds of the per-account MFA transition lock.
 *
 * Short on purpose: the lock is released in a `finally`, so this bound only matters when a
 * process dies mid-transition, and an account whose MFA is briefly unchangeable is a worse
 * outcome than a window this narrow. Long enough to cover a repository read plus a write on
 * any plausible backend.
 */
const MFA_TRANSITION_LOCK_TTL_SECONDS = 10

/**
 * Releases a lock only if it still holds the nonce the releasing call wrote.
 *
 * `GET` then `DEL` from the client cannot express this: the key can expire and be retaken
 * between the two round trips, which is the exact interleaving the nonce is there to catch.
 * One script makes the read and the delete atomic.
 *
 * KEYS[1] the lock key
 * ARGV[1] the nonce the caller wrote when it took the lock
 *
 * Returns 1 when this call's lock was released, 0 when it had already expired or been retaken.
 */
const RELEASE_LOCK_LUA = `if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0`

/** Reads and writes the MFA state of one account, serializing every write per account and plane. */
@Injectable()
export class MfaRecordService {
  private readonly logger = new Logger(MfaRecordService.name)

  constructor(
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Optional()
    @Inject(BYMAX_AUTH_PLATFORM_USER_REPOSITORY)
    private readonly platformUserRepo: IPlatformUserRepository | null,
    @Inject(AuthRedisService) private readonly redis: AuthRedisService
  ) {}

  /**
   * Store the TOTP secret re-encrypted under the current key.
   *
   * Detached from the challenge it follows: the user is already authenticated and the retired
   * key still opens the secret, so a failure here costs the migration and nothing else.
   *
   * The write replaces the whole MFA record, so it runs as a serialized transition and lands only
   * on a record that still holds this secret. One that no longer does was disabled or re-enrolled
   * since, and writing the re-encrypted old secret over it would restore a factor the user removed
   * and unspend the recovery codes they replaced. The comparison is on the decrypted secret, not
   * the ciphertext: a sibling challenge that only re-encrypted the same secret changes the
   * ciphertext and nothing else, and must not be mistaken for a re-enrolment.
   *
   * @param userId - The account whose stored secret is being re-encrypted.
   * @param context - Which identity plane the account belongs to.
   * @param secretBase32 - The decrypted secret.
   * @param tenantId - The tenant the account belongs to, so the write is scoped like the read.
   * @param keys - The secret-cipher keys; the secret is written under the current one.
   */
  async reencryptSecret(
    userId: string,
    context: 'dashboard' | 'platform',
    secretBase32: string,
    tenantId: string | undefined,
    keys: MfaSecretKeys
  ): Promise<void> {
    try {
      await this.transition(context, userId, tenantId, (current) => {
        if (!current.mfaEnabled || !holdsSecret(current.mfaSecret, secretBase32, keys)) return null
        return {
          mfaEnabled: true,
          mfaSecret: encryptMfaSecret(secretBase32, keys),
          mfaRecoveryCodes: current.mfaRecoveryCodes ?? []
        }
      })
    } catch (err: unknown) {
      this.logger.error(
        `re-encryption under the current MFA key failed: ${describeChannelStatus(err)}`
      )
    }
  }

  /**
   * Performs one MFA state transition as a serialized read-modify-write.
   *
   * Every MFA transition rewrites a single repository record that carries `mfaEnabled`, the
   * encrypted secret and the recovery-code digests **together**, and `updateMfa` replaces all
   * three wholesale — the interface offers no compare-and-set and the repository is the host's,
   * so the library cannot add one. Read-modify-write over a shared record with no CAS is
   * last-write-wins, and the three ways that bit were:
   *
   * - two challenges spending *different* recovery codes concurrently each write the full list
   *   minus their own code, so the loser's code comes back and verifies again once the `rcu:`
   *   claim expires. That claim is keyed on the code, so it serializes two attempts at the
   *   *same* code and nothing else;
   * - a challenge that read the list before `regenerateRecoveryCodes` and splices after it
   *   restores the entire old set, unspending it — precisely when the user replaced it because
   *   it leaked — while the codes they just printed are gone;
   * - a challenge that splices after `disable` completes writes `mfaEnabled: true` back with
   *   the pre-disable secret, putting the account under a factor the user removed and may no
   *   longer hold.
   *
   * The fix is to serialize the whole read-modify-write per account and plane. `mutate` is
   * handed the record as it stands **inside** the lock — never the copy the caller read
   * earlier — and returns the update to write, or `null` to abandon the transition because
   * the record moved underneath it.
   *
   * A caller that cannot take the lock is refused with `MFA_STATE_CONFLICT` rather than made to
   * wait: concurrent MFA state changes on one account are pathological, and the honest answer
   * is "try again". The lock's TTL is short so a process that dies mid-transition does not
   * strand the account, and it is released in a `finally` so an ordinary failure does not
   * either.
   *
   * @param context - Which identity plane the account belongs to.
   * @param userId - The account being transitioned.
   * @param mutate - Given the record inside the lock, returns the update or `null` to abandon.
   * @returns `true` when a write happened, `false` when `mutate` abandoned the transition.
   * @throws {@link AuthException} `MFA_STATE_CONFLICT` when another transition holds the lock.
   */
  async transition(
    context: 'dashboard' | 'platform',
    userId: string,
    tenantId: string | undefined,
    mutate: (current: AuthUser | AuthPlatformUser) => MfaRecordUpdate | null
  ): Promise<boolean> {
    // Two lock keys: the plane-only key a pod from before tenant scoping still takes, and the
    // tenant-scoped key. Acquiring BOTH keeps the transition mutually exclusive with such a pod
    // (via the plane-only key) AND with other pods at this version (via the scoped key); holding
    // only one would let two pods transition the same account at once, the very race this method
    // exists to prevent.
    //
    // **This does NOT make a rolling upgrade from 1.4.3 safe: do not deploy across that
    // boundary.** The lock key has three generations of preimage: `dashboard:{userId}` (the
    // plane-only arm below), `dashboard:{tenantId}:{userId}` (what 1.4.3 shipped) and the
    // length-prefixed subject `userSubject` builds. A pod running 1.4.3 takes the second, which
    // this code does not take, so against 1.4.3 the pair provides no exclusion and every
    // last-write-wins failure the lock exists to prevent is reachable while both are live. Drain
    // the old pods before the new ones serve; the wire contract states the same obligation for
    // the keyspace itself, which has no compatibility path either.
    //
    // The second generation is deliberately NOT a third arm: it would be compatibility weight for
    // a deployment that does not exist, and the cutover the contract requires is the stronger
    // position.
    //
    // On the platform plane the two keys coincide (the subject never carried a tenant), so the
    // plane-only arm is skipped — taking the same lock a second time would always fail and refuse
    // every platform transition.
    const scopedLockKey = `mfalock:${hmacSha256(userSubject(context, userId, tenantId), this.options.hmacKey)}`
    const legacyLockKey = `mfalock:${hmacSha256(`${context}:${userId}`, this.options.hmacKey)}`
    const acquireLegacy = legacyLockKey !== scopedLockKey
    // Both locks carry a per-call nonce so each can only be released by the call that took it.
    // A fixed value made the release unsafe: the TTL is short, and a transition that outlives
    // it — the repository is the host's, and a read plus a write can stall past ten seconds
    // under load — has already lost the lock by the time its `finally` runs. Deleting it
    // unconditionally there removes the *successor's* lock, and a third caller then enters
    // alongside the second. That is the serialization this method exists to provide, undone
    // precisely under the load that makes concurrent transitions likely in the first place.
    const lockToken = randomBytes(16).toString('hex')
    if (
      !(await this.redis.setIfAbsent(scopedLockKey, lockToken, MFA_TRANSITION_LOCK_TTL_SECONDS))
    ) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_STATE_CONFLICT)
    }
    if (
      acquireLegacy &&
      !(await this.redis.setIfAbsent(legacyLockKey, lockToken, MFA_TRANSITION_LOCK_TTL_SECONDS))
    ) {
      // Roll back the scoped lock we already hold before refusing — a compare-and-delete, never a
      // bare DEL, so a scoped lock whose TTL lapsed and was retaken by another caller is left
      // alone rather than stolen.
      await this.redis.eval(RELEASE_LOCK_LUA, [scopedLockKey], [lockToken])
      throw new AuthException(AUTH_ERROR_CODES.MFA_STATE_CONFLICT)
    }
    try {
      // Re-read inside the lock. The caller's copy was read before the lock existed and may
      // already be stale — reusing it would leave exactly the window this method closes.
      const current = await this.loadAccount(context, userId, tenantId)
      const update = mutate(current)
      if (update === null) return false
      // Narrowed to the repository contract rather than cast to it. `MfaRecordUpdate` widens to
      // `undefined` because the two planes' record types differ on the read side, but both
      // `updateMfa` contracts declare `string | null` / `string[] | null` — required, not
      // optional. A cast let `undefined` through to a consumer repository, where an ORM that
      // reads it as "leave this column alone" would write `mfaEnabled: false` while keeping
      // the secret and the recovery digests: MFA reported off, and every stored factor still
      // able to satisfy a challenge. `?? null` states the clear explicitly, and dropping the
      // casts means the compiler checks the two contracts from here on.
      const write = {
        mfaEnabled: update.mfaEnabled,
        mfaSecret: update.mfaSecret ?? null,
        mfaRecoveryCodes: update.mfaRecoveryCodes ?? null
      }
      if (context === 'platform' && this.platformUserRepo) {
        await this.platformUserRepo.updateMfa(userId, write)
      } else {
        // Narrows the tenant for the dashboard write: every dashboard entry point already ran
        // `assertPlaneTenant`, but only this form is one the type system reads.
        assertDashboardTenant(tenantId)
        await this.userRepo.updateMfa({ id: userId, tenantId, data: write })
      }
      return true
    } finally {
      // Compare-and-delete each: release only a lock still holding this call's nonce, and only the
      // legacy lock if this call actually took it.
      await this.redis.eval(RELEASE_LOCK_LUA, [scopedLockKey], [lockToken])
      if (acquireLegacy) {
        await this.redis.eval(RELEASE_LOCK_LUA, [legacyLockKey], [lockToken])
      }
    }
  }

  /**
   * Claims a matched recovery code for exactly one challenge.
   *
   * Consuming a code is a read-modify-write against the consumer's repository: the challenge
   * reads the whole array, removes one entry, and writes the rest back. Two challenges landing
   * together both read the array containing the code, both match it, and both write — one code
   * mints two sessions, which is the one property a recovery code has. The library cannot fix
   * that in the repository, because the repository is the consumer's and its atomicity is
   * theirs to define. It can fix it in the store it owns.
   *
   * `SET NX` over an HMAC of plane + user + code is the same primitive the TOTP anti-replay
   * marker already uses, for the same reason and with the same properties: the key discloses
   * neither the user nor the code, and it cannot be shared across identity planes whose id
   * spaces may collide. The first claim wins; every other reads as an invalid code, which is
   * what a code already spent is.
   *
   * The marker is deliberately short-lived. It exists to serialize a race measured in
   * milliseconds, not to be the durable record — that is the repository write. Outliving the
   * write by much would turn a failed write into a permanently unusable code that is still
   * sitting in the account's list.
   *
   * @param context - The identity plane the challenge belongs to.
   * @param userId - The account the code belongs to.
   * @param code - The submitted code, never stored — only its keyed MAC becomes a key.
   * @returns `true` when this challenge is the one that claimed it.
   */
  async claimRecoveryCode(
    context: 'dashboard' | 'platform',
    userId: string,
    code: string,
    tenantId: string | undefined
  ): Promise<boolean> {
    // The claim marker is keyed by the tenant-scoped subject, like every other MFA key, so a claim
    // written under an older preimage is not consulted: deploying alongside pods on an older
    // version lets the same recovery code be claimed once on each side.
    //
    // The transition lock does not bound that. It is keyed by the same subject, so pods that
    // disagree about the subject disagree about the lock and do not exclude each other (see the
    // note in `transition`). A double claim then reaches two unserialized read-modify-writes on
    // the recovery-code list, which is how a spent code comes back.
    //
    // The answer is the deployment shape, not a wider key: old pods must be drained before the
    // new ones serve. The marker is short-lived, so once no older pod is live there is nothing
    // left to reconcile.
    const claimKey = `rcu:${hmacSha256(`${userSubject(context, userId, tenantId)}:${code}`, this.options.hmacKey)}`
    return await this.redis.setnx(claimKey, RECOVERY_CODE_CLAIM_TTL_SECONDS)
  }

  /**
   * Verifies a TOTP code and enforces anti-replay within the validation window.
   *
   * Stores a Redis key `tu:{hmac}` where `hmac = hmacSha256("{userSubject}:{code}", hmacKey)` —
   * so the marker is scoped to the plane and, on the dashboard plane, to the tenant. A second
   * submission of the same code within the TTL is rejected as a replay. Binding the marker to
   * both the subject and the code value prevents code disclosure in Redis and cross-user,
   * cross-tenant and cross-plane replay alike.
   *
   * A second marker under the plane-only preimage `{context}:{userId}:{code}` is written and
   * required alongside it; see the call site for why both must be fresh while pods of two
   * versions are live.
   *
   * @returns `true` if the code is valid and has not been replayed, `false` otherwise.
   */
  async verifyTotpWithAntiReplay(
    context: 'dashboard' | 'platform',
    userId: string,
    secretBase32: string,
    code: string,
    window: number,
    tenantId: string | undefined
  ): Promise<boolean> {
    if (!verifyTotp(secretBase32, code, window)) return false

    // The HMAC ties the replay key to the tenant-scoped subject and the specific code — preventing
    // cross-tenant AND cross-plane replay, and avoiding plaintext code storage in Redis. Two
    // tenants' user `1` do not share a marker, so one cannot burn the other's code.
    const ttl = totpAntiReplayTtlSeconds(window)
    const scopedReplayKey = `tu:${hmacSha256(`${userSubject(context, userId, tenantId)}:${code}`, this.options.hmacKey)}`
    const legacyReplayKey = `tu:${hmacSha256(`${context}:${userId}:${code}`, this.options.hmacKey)}`
    // Fresh only when unclaimed on BOTH keys: while pods of two versions are live, an old pod
    // claims only the plane-only key and a new pod only the scoped one, so consulting a single key
    // would let the same code pass once on each side. Setting both and requiring both new closes
    // the replay across the two code paths; a marker left by the losing conjunct expires on its
    // own. On the platform plane the two keys coincide — claiming the scoped one a second time
    // would always read as a replay and reject every code — so the second claim is skipped there.
    const scopedIsNew = await this.redis.setnx(scopedReplayKey, ttl)
    if (scopedReplayKey === legacyReplayKey) return scopedIsNew
    const legacyIsNew = await this.redis.setnx(legacyReplayKey, ttl)
    return scopedIsNew && legacyIsNew
  }

  /**
   * Fetches a user from the correct repository based on the MFA context, and refuses one whose
   * account is blocked.
   *
   * The status gate lives here rather than in each caller because every entry point that
   * reaches this method changes or spends an authentication factor, and every one of them
   * must refuse a suspended or banned account. A gate in `challenge` alone would leave `setup`,
   * `verifyAndEnable`, `disable` and `regenerateRecoveryCodes` open: an operator who suspended a
   * compromised account would buy nothing against an attacker still holding an unexpired access
   * token, who could turn the second factor off — or enrol their own authenticator over it — for
   * the token's remaining lifetime. Nothing else covers that window: no status change bumps the
   * token epoch, so the per-request check is the only defence, and neither MFA controller
   * composes `UserStatusGuard` (the platform plane has no status guard at all). Every other
   * authority-bearing route in the library does gate on status; changing an authentication
   * factor is at least as privileged as minting an invitation.
   *
   * Gating the fetch rather than the callers is deliberate: a method added later inherits the
   * check instead of having to remember it.
   *
   * @param context - Which identity plane the caller is acting on.
   * @param userId - The subject taken from the verified token.
   * @param tenantId - The tenant the caller was authenticated in, on the dashboard plane;
   *   absent on the platform plane, whose admins belong to none.
   * @returns The account record, guaranteed to be in good standing.
   * @throws `TOKEN_INVALID` if the user is not found.
   * @throws {@link AuthException} the status error when the account is blocked.
   */
  async loadAccount(
    context: 'dashboard' | 'platform',
    userId: string,
    tenantId?: string
  ): Promise<AuthUser | AuthPlatformUser> {
    if (context === 'dashboard') {
      assertDashboardTenant(tenantId)
      // Scoped to the tenant the caller was authenticated in — the JWT's `tenantId` on the
      // dashboard-authenticated flows, the challenge token's on the MFA challenge. A repository id
      // is unique only within a tenant, so an unscoped read could return, and this then decides
      // status / secret / session against, a homonym in another tenant. The assertion above is
      // what makes that a compile-time fact rather than a claim about the callers: the entry
      // points do all refuse a dashboard flow without a tenant, but a `void` guard narrows
      // nothing, so the read cannot accept `string | undefined` on the strength of prose.
      const user = await this.userRepo.findById({ id: userId, tenantId })
      if (!user) throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
      assertNotBlocked(user.status, this.options.blockedStatuses)
      return user
    }

    if (!this.platformUserRepo) {
      // Misconfiguration: consumer set controllers.mfa: true without supplying
      // BYMAX_AUTH_PLATFORM_USER_REPOSITORY in extraProviders. Throw AuthException so
      // NestJS exception filters produce a clean response rather than leaking internal details.
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
    const admin = await this.platformUserRepo.findById(userId)
    if (!admin) throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    assertNotBlocked(admin.status, this.options.blockedStatuses)
    return admin
  }
}
