import { randomBytes } from 'node:crypto'

import { Inject, Injectable, Logger, Optional } from '@nestjs/common'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { BruteForceService } from './brute-force.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'
import type { ResolvedOptions } from '../config/resolved-options'
import { recentAuthKey } from '../constants/recent-auth'
import { userSubject } from '../constants/user-subject'
import { decrypt, encrypt } from '../crypto/aes-gcm'
import { hmacSha256, timingSafeCompare } from '../crypto/secure-token'
import {
  buildTotpUri,
  generateTotpSecret,
  MAX_VERIFY_WINDOW,
  TOTP_STEP_SECONDS,
  verifyTotp
} from '../crypto/totp'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { AuthResult, PlatformAuthResult } from '../interfaces/auth-result.interface'
import type { IEmailProvider } from '../interfaces/email-provider.interface'
import type {
  AuthPlatformUser,
  IPlatformUserRepository,
  SafeAuthPlatformUser
} from '../interfaces/platform-user-repository.interface'
import type {
  AuthUser,
  IUserRepository,
  SafeAuthUser
} from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { assertNotBlocked } from '../utils/assert-not-blocked'
import { describeChannelStatus } from '../utils/describe-error'
import { logSafe } from '../utils/log-safe'
import { safeLogLine } from '../utils/safe-log-line'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** TTL in seconds for the pending MFA setup data (10 minutes). */
/**
 * The tenant a platform-plane MFA notice is attributed to. A platform admin is cross-tenant and
 * carries no `tenantId`, but the email port takes one for a notification backend's audit
 * attribution and routing; `'platform'` names that plane, mirroring the `pep:` epoch namespace.
 *
 * This is a **reserved** attribution, not a real tenant: because tenant ids are arbitrary strings,
 * a dashboard tenant literally named `'platform'` would otherwise be indistinguishable from the
 * admin plane at the port. A deployment that lets tenants choose their own id must keep this one
 * out of that space, the same way `pep:`/`ep:` keep the two epoch namespaces from colliding in
 * Redis. A single-tenant provider ignores the value and the question does not arise.
 */
const PLATFORM_EMAIL_TENANT = 'platform'

/**
 * The tenant an MFA email is attributed to: a dashboard user's own tenant, or the platform plane
 * for a cross-tenant admin who carries none.
 *
 * @param user - The dashboard or platform user the notice is about.
 * @returns The tenant id for the email port.
 */
function emailTenantOf(user: AuthUser | AuthPlatformUser): string {
  return 'tenantId' in user ? user.tenantId : PLATFORM_EMAIL_TENANT
}

const MFA_SETUP_TTL_SECONDS = 600

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
 * This used to be a hard-coded 90: exactly right for the default window of 1, and silently
 * short for any larger one — which the configuration allowed, so `totpWindow: 2` accepted
 * codes for 150 s while the marker expired at 90 and the last 60 s were replayable.
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
interface MfaRecordUpdate {
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

/** Number of recovery codes generated when MFA is enabled. */
const DEFAULT_RECOVERY_CODE_COUNT = 8

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Result returned by {@link MfaService.setup} containing the TOTP secret,
 * a QR code URI for authenticator apps, and the one-time plain-text recovery codes.
 *
 * @remarks
 * `recoveryCodes` must be displayed to the user **once** at setup time and never
 * stored in plain text — the service stores a keyed HMAC-SHA-256 of each one.
 * `secret` is provided for manual entry in authenticator apps that cannot scan a QR code.
 */
export interface MfaSetupResult {
  /** Base32-encoded TOTP secret for manual entry in authenticator apps. */
  secret: string
  /** `otpauth://totp/` URI for QR code generation. */
  qrCodeUri: string
  /** Plain-text recovery codes. Display once and never persist in this form. */
  recoveryCodes: string[]
}

/**
 * Shape stored in Redis during a pending MFA setup.
 *
 * `encryptedSecret` and `encryptedPlainCodes` are both AES-256-GCM encrypted so
 * that a Redis compromise during the 10-minute setup window does not expose the
 * TOTP secret or plain-text recovery codes.
 *
 * @internal
 */
interface MfaSetupData {
  /** AES-256-GCM encrypted Base32 TOTP secret. */
  encryptedSecret: string
  /** Keyed HMAC-SHA-256 digests of the recovery codes (stored in the DB after enable). */
  hashedCodes: string[]
  /**
   * AES-256-GCM encrypted JSON array of plain-text recovery codes.
   * Stored only to support idempotent re-display within the setup window.
   */
  encryptedPlainCodes: string
}

/**
 * Whether an unknown value is a well-formed {@link MfaSetupData}.
 *
 * @param value - The `JSON.parse` result.
 * @returns `true` when every field is present and correctly typed.
 */
function isMfaSetupData(value: unknown): value is MfaSetupData {
  if (value === null) return false
  // Unobservable either way. A primitive answers `undefined` to every field read below, so the
  // conjunction returns false without this arm, and returning true from it hands the caller a
  // value whose fields are all `undefined` — refused a step later by the same MFA_SETUP_REQUIRED.
  // Only `null` has to be stopped before the reads, because taking a property off it throws.
  // Kept as a stated precondition rather than as behaviour.
  //
  // Stryker disable ConditionalExpression,BooleanLiteral: subsumed by the field reads below
  if (typeof value !== 'object') return false
  // Stryker restore ConditionalExpression,BooleanLiteral
  const v = value as Record<string, unknown>
  return (
    typeof v['encryptedSecret'] === 'string' &&
    typeof v['encryptedPlainCodes'] === 'string' &&
    Array.isArray(v['hashedCodes']) &&
    v['hashedCodes'].every((code) => typeof code === 'string')
  )
}

// ---------------------------------------------------------------------------
// MfaService
// ---------------------------------------------------------------------------

/**
 * The `VALIDATION` detail both plane-tenant guards answer with.
 *
 * One string, because the two halves are one rule read from opposite sides — a dashboard call
 * without a tenant and a platform call with one are the same mistake, made on the wrong plane.
 * A caller that starts seeing this needs to know both halves whichever half it tripped, and two
 * copies drift the moment one is reworded.
 */
const PLANE_TENANT_MESSAGE =
  'tenantId must be a non-empty value on the dashboard plane and absent on the platform plane'

/**
 * Manages TOTP-based multi-factor authentication lifecycle.
 *
 * Handles the complete MFA flow for both dashboard users and platform admins:
 * - **Setup**: generate TOTP secret + recovery codes, store temporarily in Redis
 * - **Verify & Enable**: confirm first TOTP code, persist encrypted secret to DB
 * - **Challenge**: exchange a valid MFA temp token + code for full access tokens
 * - **Disable**: require a current TOTP code to disable MFA
 *
 * @remarks
 * This service is only registered when `options.mfa` is configured in
 * `BymaxAuthModule.registerAsync()`. All crypto operations use `node:crypto` only.
 *
 * @layer Service
 */
@Injectable()
export class MfaService {
  private readonly logger = new Logger(MfaService.name)

  constructor(
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Optional()
    @Inject(BYMAX_AUTH_PLATFORM_USER_REPOSITORY)
    private readonly platformUserRepo: IPlatformUserRepository | null,
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    @Inject(TokenManagerService) private readonly tokenManager: TokenManagerService,
    @Inject(BruteForceService) private readonly bruteForce: BruteForceService,
    @Inject(PasswordService) private readonly passwordService: PasswordService,
    @Inject(SessionService) private readonly sessionService: SessionService,
    @Inject(BYMAX_AUTH_EMAIL_PROVIDER) private readonly emailProvider: IEmailProvider,
    @Inject(BYMAX_AUTH_HOOKS) private readonly hooks: IAuthHooks
  ) {}

  // ---------------------------------------------------------------------------
  // Private accessor — options.mfa is guaranteed non-null when service is active
  // ---------------------------------------------------------------------------

  /**
   * Returns the resolved MFA configuration. `options.mfa` is always present when `MfaService` is registered.
   *
   * `options.mfa` is always present when `MfaService` is registered — the module
   * only registers the service when `mfa` is configured. The single suppression
   * here eliminates repetitive `!` assertions throughout the class.
   */
  private get mfaOptions(): Required<NonNullable<ResolvedOptions['mfa']>> {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return this.options.mfa!
  }

  // ---------------------------------------------------------------------------
  // Private crypto helpers
  // ---------------------------------------------------------------------------

  /**
   * Store the TOTP secret re-encrypted under the current key.
   *
   * Detached from the challenge it follows: the user is already authenticated and the retired
   * key still opens the secret, so a failure here costs the migration and nothing else.
   *
   * @param userId - The account whose stored secret is being re-encrypted.
   * @param context - Which identity plane the account belongs to.
   * @param secretBase32 - The decrypted secret.
   * @param recoveryCodes - The stored recovery digests, written back unchanged.
   * @param tenantId - The tenant the account belongs to, so the write is scoped like the read.
   */
  private async reencryptSecret(
    userId: string,
    context: 'dashboard' | 'platform',
    secretBase32: string,
    recoveryCodes: string[],
    tenantId: string | undefined
  ): Promise<void> {
    const update = {
      mfaEnabled: true as const,
      mfaSecret: this.encryptSecret(secretBase32),
      mfaRecoveryCodes: recoveryCodes
    }
    try {
      if (context === 'platform' && this.platformUserRepo) {
        await this.platformUserRepo.updateMfa(userId, update)
      } else {
        // Narrows the tenant for the dashboard write. Every dashboard entry point already ran
        // `assertPlaneTenant`, so this re-states a settled fact rather than discovering one —
        // but it is the only form the type system reads, and `updateMfa` requires a tenant for
        // the same reason `findById` does.
        this.assertDashboardTenant(tenantId)
        await this.userRepo.updateMfa(userId, tenantId, update)
      }
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
  private async transitionMfaRecord(
    context: 'dashboard' | 'platform',
    userId: string,
    tenantId: string | undefined,
    mutate: (current: AuthUser | AuthPlatformUser) => MfaRecordUpdate | null
  ): Promise<boolean> {
    // Two lock keys for one release: the legacy plane-only key an old pod still takes, and the
    // tenant-scoped key this release takes. Acquiring BOTH keeps the transition mutually exclusive
    // with a PRE-TENANT pod (via the legacy key) AND other pods on this release (via the scoped
    // key) — holding only one would let two pods transition the same account at once, the very
    // race this method exists to prevent.
    //
    // **It does NOT make a rolling upgrade from 1.4.3 safe, and this release must not be deployed
    // as one.** There are three generations of this preimage, not two: `dashboard:{userId}` (the
    // legacy arm below), `dashboard:{tenantId}:{userId}` (what 1.4.3 shipped) and the
    // length-prefixed subject `userSubject` builds now. The legacy arm covers the first. A pod
    // still running 1.4.3 takes the SECOND, which this code takes neither of — so against 1.4.3
    // the pair provides no exclusion at all, and every last-write-wins failure the lock exists to
    // prevent is reachable while both are live. Drain the old pods before the new ones serve;
    // the wire contract states the same obligation for the keyspace itself, which has no
    // compatibility path either.
    //
    // The second generation is deliberately NOT added as a third arm. It would be compatibility
    // weight for a deployment that does not exist — the library has no consumers yet — and the
    // cutover the contract already requires is the stronger of the two positions.
    //
    // On the platform plane the two keys coincide (the subject never carried a tenant), so the
    // legacy arm is skipped — taking the same lock a second time would always fail and refuse every
    // platform transition.
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
      const current = await this.fetchUserForContext(context, userId, tenantId)
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
        // Narrows the tenant for the dashboard write, as in `reencryptSecret`.
        this.assertDashboardTenant(tenantId)
        await this.userRepo.updateMfa(userId, tenantId, write)
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
   * Encrypts a TOTP secret for storage in the database using AES-256-GCM.
   */
  private encryptSecret(secret: string): string {
    return encrypt(secret, this.mfaOptions.encryptionKey)
  }

  /**
   * Decrypts a stored TOTP secret, falling back to keys retired by a rotation.
   *
   * The ciphertext records no key identifier, so without the retired keys, changing
   * `mfa.encryptionKey` makes every stored secret undecryptable — every enrolled user's
   * authenticator stops matching at once, with no way back. AES-GCM authenticates, so a wrong
   * key fails unambiguously rather than returning garbage; trying them in order is safe.
   *
   * Re-throws any decryption failure as an opaque `TOKEN_INVALID` to prevent
   * error-type oracle attacks (callers cannot distinguish format vs. tamper errors).
   */
  private decryptSecret(encrypted: string): string {
    return this.decryptWithRotation(encrypted).secret
  }

  /**
   * Decrypt under the current key, then under each retired one.
   *
   * @param encrypted - The stored ciphertext.
   * @returns The plaintext and whether a retired key produced it — the signal that the record
   *   should be re-encrypted under the current key.
   * @throws {@link AuthException} `TOKEN_INVALID` when no key decrypts it.
   */
  private decryptWithRotation(encrypted: string): { secret: string; stale: boolean } {
    try {
      return { secret: decrypt(encrypted, this.mfaOptions.encryptionKey), stale: false }
    } catch {
      for (const key of this.mfaOptions.previousEncryptionKeys ?? []) {
        try {
          return { secret: decrypt(encrypted, key), stale: true }
        } catch {
          // Try the next retired key. A ciphertext none of them opens is tampered, truncated,
          // or from a key nobody holds any more — all the same opaque failure to the caller.
        }
      }
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
  }

  /**
   * Safely parses a Redis-stored {@link MfaSetupData} JSON payload.
   *
   * A corrupted or tampered Redis value would otherwise raise an unhandled
   * `SyntaxError` from the service boundary (uncaught 500). We translate the
   * failure into an opaque `MFA_SETUP_REQUIRED`, which mirrors the response
   * the caller would receive if the key were absent — preventing an attacker
   * with Redis write access from distinguishing "no setup pending" from
   * "setup payload corrupted".
   */
  private parseSetupData(raw: string, userId: string): MfaSetupData {
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      // Recorded, not just refused. The caller gets an opaque MFA_SETUP_REQUIRED — correct, since
      // it must learn nothing about the payload's structure — which leaves this line as the only
      // trace of an event the docstring above calls either a downgrade of the stored value or an
      // internal bug. Both are things an operator needs to see, and neither is visible anywhere
      // else.
      this.logger.warn(
        `parseSetupData: pending-setup payload is not valid JSON userId=${logSafe(userId)}`
      )
      throw new AuthException(AUTH_ERROR_CODES.MFA_SETUP_REQUIRED)
    }
    // The shape is checked, not asserted. `hashedCodes` missing would enable MFA on an
    // account with no recovery codes at all — a lockout waiting to happen that the user
    // discovers only when they lose their authenticator. `rust-auth` deserializes into a
    // struct with every field required, so a record like that is refused there too.
    if (!isMfaSetupData(parsed)) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_SETUP_REQUIRED)
    }
    return parsed
  }

  /**
   * Safely parses the AES-decrypted JSON array of plain-text recovery codes.
   *
   * A decrypted value that fails JSON parsing indicates either a downgrade of
   * the stored payload (highly unlikely, since AES-GCM authenticates the
   * ciphertext) or an internal bug. Both cases are surfaced opaquely as
   * `MFA_SETUP_REQUIRED` so callers do not learn structural details of the
   * encrypted payload.
   */
  private parsePlainRecoveryCodes(raw: string, userId: string): string[] {
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      // Same reasoning as `parseSetupData`, and a stronger case: AES-GCM authenticates the
      // ciphertext, so a decrypted value that will not parse means the plaintext itself was
      // written wrong. That is an internal bug, and it is otherwise silent.
      this.logger.warn(
        `parsePlainRecoveryCodes: decrypted payload is not valid JSON userId=${logSafe(userId)}`
      )
      throw new AuthException(AUTH_ERROR_CODES.MFA_SETUP_REQUIRED)
    }
    if (!Array.isArray(parsed) || parsed.some((code) => typeof code !== 'string')) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_SETUP_REQUIRED)
    }
    return parsed as string[]
  }

  /**
   * Generates `count` recovery codes in `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` format
   * (96 bits of entropy per code, hex-encoded).
   *
   * Returns both the plain-text (shown once to the user) and scrypt-hashed
   * versions (stored in the database).
   *
   * @remarks
   * Each code carries 96 bits of entropy (12 random bytes → 24 hex chars grouped
   * as 6 × 4). This is well above the NIST SP 800-63B recommendation for
   * offline-resistant credentials. The previous 12-digit decimal format offered
   * ~40 bits, which relied entirely on the scrypt hash for offline resistance —
   * any database leak would have put the raw codes within offline reach.
   */
  private hashRecoveryCodes(count: number): { plainCodes: string[]; hashedCodes: string[] } {
    const plainCodes: string[] = []
    const hashedCodes: string[] = []

    for (let i = 0; i < count; i++) {
      // 12 random bytes → 24 hex characters → 96-bit entropy.
      // Grouped as 6 × 4 for better user readability when typed manually.
      // Build the groups via a deterministic slice loop rather than RegExp.match,
      // so the type narrows cleanly without a non-null assertion.
      const hex = randomBytes(12).toString('hex')
      const groups: string[] = []
      for (let offset = 0; offset < hex.length; offset += 4) {
        groups.push(hex.slice(offset, offset + 4))
      }
      const code = groups.join('-').toUpperCase()
      plainCodes.push(code)
      hashedCodes.push(this.digestRecoveryCode(code))
    }

    return { plainCodes, hashedCodes }
  }

  /**
   * Derives the stored digest for a recovery code: a keyed HMAC-SHA-256, hex encoded.
   *
   * A recovery code is 96 bits of CSPRNG output, not a human-chosen password, so a
   * memory-hard KDF buys nothing against it — there is no dictionary to walk and brute
   * forcing 2^96 is out of reach whatever the hash costs. What the KDF did buy was an
   * attacker-reachable CPU amplifier: a challenge submitting a wrong recovery code scanned
   * every stored digest, so one request cost as many scrypt derivations as the user had
   * codes. The keyed MAC is the right primitive here — the secret key is what stops an
   * offline attacker precomputing digests from a leaked table, and it costs microseconds.
   */
  private digestRecoveryCode(code: string): string {
    return hmacSha256(code, this.options.hmacKey)
  }

  /**
   * Compares a submitted recovery code against every stored digest.
   *
   * One storage format only: a keyed MAC over the code. Every digest is compared in constant
   * time and the scan always runs to completion — including the step that picks the winner out
   * of the recorded results — so neither the position of a match nor the number of codes still
   * unused is observable in the response time.
   *
   * @returns Index of the first matching digest, or `-1` if none match.
   */
  private async verifyRecoveryCode(code: string, hashedCodes: string[]): Promise<number> {
    // One candidate per key in play: the current one, then any retired by a rotation. The
    // digest is keyed by an HMAC derived from `jwt.secret`, so without the retired keys a
    // rotation would silently invalidate every code a user has printed and filed — they would
    // discover it at the moment they most need it. Retired keys verify only; a code that
    // matches one is consumed and the set is regenerated under the current key.
    const candidates = [
      this.digestRecoveryCode(code),
      ...this.options.previousHmacKeys.map((key) => hmacSha256(code, key))
    ]
    const macMatches: boolean[] = []

    for (const hashedCode of hashedCodes) {
      // Every candidate is compared, never short-circuited: stopping at the first hit would
      // make the scan's duration report how many keys were tried before the match. `reduce`
      // visits the whole list by construction, and the comparison is the left operand of `||`
      // so it is evaluated on every step regardless of what has already matched.
      const hit = candidates.reduce(
        (found, candidate) => timingSafeCompare(candidate, hashedCode) || found,
        false
      )
      macMatches.push(hit)
    }

    // Recording every comparison and picking the first hit afterwards, rather than tracking the
    // winner inside the loop, keeps the scan uniform: the same work happens whether the match
    // is at the front, at the back, or absent.
    //
    // Reduced rather than `indexOf`, which stops at the first hit — the tail of the scan then
    // runs shorter for an early match than for a late one or none, which is the position signal
    // the loop above exists to avoid, reintroduced on the last line of it. The reduction visits
    // every entry, and the first hit wins because a later one cannot overwrite a set index.
    // `-1` for no match is the contract this method already had.
    return macMatches.reduce((found, hit, index) => (found === -1 && hit ? index : found), -1)
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
  private async claimRecoveryCode(
    context: 'dashboard' | 'platform',
    userId: string,
    code: string,
    tenantId: string | undefined
  ): Promise<boolean> {
    // The claim marker is keyed by the tenant-scoped subject, like every other MFA key, and it
    // takes an ORPHAN CUTOVER: a claim written under an older preimage is not consulted after the
    // upgrade. Deploying this release alongside pods on an older one lets the same recovery code
    // be claimed once on each side.
    //
    // That is not bounded by `mutate`'s transition lock, and the earlier version of this comment
    // was wrong to imply the repository write would arbitrate it. The lock is keyed by the SAME
    // subject, so pods that disagree about the subject disagree about the lock too and do not
    // exclude each other at all — see the note there. A double claim then reaches two unserialized
    // read-modify-writes on the recovery-code list, which is precisely how a spent code comes back.
    //
    // The answer is the deployment shape, not a wider key: this release is a cutover, and the old
    // pods must be drained before the new ones serve. The marker is short-lived, so once no older
    // pod is live there is nothing left to reconcile.
    const claimKey = `rcu:${hmacSha256(`${userSubject(context, userId, tenantId)}:${code}`, this.options.hmacKey)}`
    return await this.redis.setnx(claimKey, RECOVERY_CODE_CLAIM_TTL_SECONDS)
  }

  /**
   * Returns a `SafeAuthUser` projection of a dashboard user, stripping credentials
   * and MFA secret fields before passing to hooks or email providers.
   */
  private toSafeUser(user: AuthUser): SafeAuthUser {
    const { passwordHash: _ph, mfaSecret: _ms, mfaRecoveryCodes: _mrc, ...safe } = user
    return safe
  }

  /**
   * Returns a `SafeAuthPlatformUser` projection of a platform admin, stripping
   * credentials and MFA secret fields.
   */
  private toSafePlatformUser(admin: AuthPlatformUser): SafeAuthPlatformUser {
    const { passwordHash: _ph, mfaSecret: _ms, mfaRecoveryCodes: _mrc, ...safe } = admin
    return safe
  }

  /**
   * Constructs a `SafeAuthUser`-compatible object from a `SafeAuthPlatformUser` so
   * that it can be passed to hooks typed for `SafeAuthUser`.
   *
   * Platform admins have no `tenantId` or `emailVerified` fields. These are filled
   * with sentinel values (`''` and `true` respectively) since platform admins are
   * provisioned directly and do not participate in the tenant/email-verification flow.
   */
  private platformUserAsSafeUser(admin: AuthPlatformUser): SafeAuthUser {
    const safe = this.toSafePlatformUser(admin)
    return {
      ...safe,
      tenantId: '',
      emailVerified: true
    }
  }

  // ---------------------------------------------------------------------------
  // setup — TOTP secret generation, idempotent key reservation, recovery codes
  // ---------------------------------------------------------------------------

  /**
   * Initiates the MFA setup flow for a dashboard user or platform administrator.
   *
   * Generates a TOTP secret and 8 recovery codes, stores them temporarily in
   * Redis (10 minutes), and returns the data needed to display the QR code and
   * recovery codes to the user.
   *
   * Idempotent: concurrent or repeated calls within the TTL window all receive the
   * same secret and codes. An atomic SET-NX is used so that two simultaneous setup
   * requests cannot generate different secrets.
   *
   * @param userId - Internal ID of the user enabling MFA.
   * @param context - Which repository to use: `'dashboard'` (default) or `'platform'`.
   * @returns Setup result containing the secret, QR URI, and plain recovery codes.
   * @throws `MFA_ALREADY_ENABLED` if MFA is already active on the account.
   * @throws `MFA_NOT_ENABLED` if `context === 'platform'` and the platform user
   *   repository was not configured at module registration. The error code is
   *   reused (rather than introducing a new one) because the consumer-facing
   *   meaning is the same: "platform MFA cannot operate".
   */
  async setup(
    userId: string,
    context: 'dashboard' | 'platform' = 'dashboard',
    password?: string,
    tenantId?: string
  ): Promise<MfaSetupResult> {
    this.assertPlaneTenant(context, tenantId)
    if (context === 'platform' && !this.platformUserRepo) {
      // Misconfiguration: caller asked for a platform setup but the host
      // application did not register BYMAX_AUTH_PLATFORM_USER_REPOSITORY.
      // Failing fast here surfaces the bug at the first request rather than
      // letting the flow silently fall back to the dashboard repo (which
      // would persist the platform admin's MFA secret on a tenant user row).
      throw new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)
    }

    const user = await this.fetchUserForContext(context, userId, tenantId)
    if (user.mfaEnabled) throw new AuthException(AUTH_ERROR_CODES.MFA_ALREADY_ENABLED)

    // Re-authenticate before minting a factor. Enabling MFA is a change to how the account
    // authenticates, and an access token alone is not proof of who is asking: a token lifted
    // by XSS or a shared machine could enrol an authenticator the attacker holds, and the
    // enable then invalidates the sessions and bumps the epoch — locking the real owner out
    // of the account they still know the password to, with the recovery codes displayed only
    // to the attacker. ASVS requires re-authentication before changing an authentication
    // factor; `disable` already honours that by demanding a TOTP code. Gating `setup` rather
    // than `verify-enable` means the attacker cannot even obtain a secret they control, and
    // it costs the user one prompt at the natural moment.
    //
    // An account with no local password — provisioned purely through OAuth — has nothing to
    // re-authenticate against here, and refusing it would make MFA unreachable for those
    // users. Their credential is the provider's, which this library cannot re-verify inline.
    await this.assertReauthenticated(context, userId, user.passwordHash, password, tenantId)

    // Key is HMAC-keyed so the Redis keyspace does not expose user IDs.
    const setupKey = `mfa_setup:${hmacSha256(userSubject(context, userId, tenantId), this.options.hmacKey)}`

    // Fast-path idempotency check: if a setup payload already exists for this user,
    // return it without performing the expensive scrypt + AES work. This prevents a
    // CPU-amplification vector where an attacker who has captured a user's access
    // token could repeatedly hit /mfa/setup and force N × scrypt calls per request
    // (each request would hash `recoveryCodeCount` codes only to lose the SET-NX race).
    // The narrow TOCTOU window between this fast-path GET and the SET-NX below is
    // benign — at worst, two concurrent first-time setups race and one's payload is
    // discarded by SET-NX after wasted work; subsequent requests hit the fast path.
    const existingFast = await this.redis.get(setupKey)
    if (existingFast !== null) {
      const data = this.parseSetupData(existingFast, userId)
      const existingSecret = this.decryptSecret(data.encryptedSecret)
      const decryptedCodesJson = this.decryptSecret(data.encryptedPlainCodes)
      const existingCodes = this.parsePlainRecoveryCodes(decryptedCodesJson, userId)
      const qrCodeUri = buildTotpUri(existingSecret, user.email, this.mfaOptions.issuer)
      return { secret: existingSecret, qrCodeUri, recoveryCodes: existingCodes }
    }

    // First-time setup: generate the data, then attempt an atomic SET-NX to claim
    // the key. The pre-generation is required to keep SET-NX atomic — two concurrent
    // requests both see null in the fast path, both generate, and SET-NX awards the
    // key to one of them. The losing request reads the winner's payload below.
    const { base32: secretBase32 } = generateTotpSecret()
    const encryptedSecret = this.encryptSecret(secretBase32)
    const recoveryCount = this.mfaOptions.recoveryCodeCount ?? DEFAULT_RECOVERY_CODE_COUNT
    const { plainCodes, hashedCodes } = this.hashRecoveryCodes(recoveryCount)
    const encryptedPlainCodes = encrypt(JSON.stringify(plainCodes), this.mfaOptions.encryptionKey)

    const setupData: MfaSetupData = { encryptedSecret, hashedCodes, encryptedPlainCodes }
    const payload = JSON.stringify(setupData)

    const wasSet = await this.redis.setIfAbsent(setupKey, payload, MFA_SETUP_TTL_SECONDS)

    if (!wasSet) {
      // Another request already started setup — return their data for idempotency.
      const existing = await this.redis.get(setupKey)
      if (existing !== null) {
        const data = this.parseSetupData(existing, userId)
        const existingSecret = this.decryptSecret(data.encryptedSecret)
        const decryptedCodesJson = this.decryptSecret(data.encryptedPlainCodes)
        const existingCodes = this.parsePlainRecoveryCodes(decryptedCodesJson, userId)
        const qrCodeUri = buildTotpUri(existingSecret, user.email, this.mfaOptions.issuer)
        return { secret: existingSecret, qrCodeUri, recoveryCodes: existingCodes }
      }
      // Extremely rare: key expired between setIfAbsent and get — store our data.
      // A concurrent verifyAndEnable that completed just before this branch is
      // safe: verifyAndEnable checks mfaEnabled at entry via findById, so a
      // re-enabled account will throw MFA_ALREADY_ENABLED on the next setup call.
      await this.redis.set(setupKey, payload, MFA_SETUP_TTL_SECONDS)
    }

    const qrCodeUri = buildTotpUri(secretBase32, user.email, this.mfaOptions.issuer)
    this.logger.log(`setup: MFA setup initiated userId=${logSafe(userId)} context=${context}`)
    return { secret: secretBase32, qrCodeUri, recoveryCodes: plainCodes }
  }

  // ---------------------------------------------------------------------------
  // verifyAndEnable — first-time TOTP validation and permanent MFA activation
  // ---------------------------------------------------------------------------

  /**
   * Verifies the first TOTP code from the user's authenticator app and permanently
   * enables MFA on the account.
   *
   * After enabling, all existing refresh sessions are atomically invalidated to
   * force re-authentication through the MFA challenge endpoint. Active access tokens
   * (up to `accessExpiresIn`, default 15 min) remain valid — they are not
   * blacklisted since the library does not track JTIs server-side.
   *
   * @param userId - Internal ID of the user completing MFA setup.
   * @param code - 6-digit TOTP code from the authenticator app.
   * @param ip - Client IP address (forwarded to hooks).
   * @param userAgent - User-Agent header (forwarded to hooks).
   * @param context - Which repository to use: `'dashboard'` (default) or `'platform'`.
   * @throws {@link AuthException} MFA_ALREADY_ENABLED when MFA is already active on the account.
   * @throws `MFA_SETUP_REQUIRED` if no pending setup data is found in Redis.
   * @throws `MFA_INVALID_CODE` if the submitted TOTP code is invalid.
   * @throws `MFA_NOT_ENABLED` if `context === 'platform'` and the platform user
   *   repository was not configured at module registration.
   */
  async verifyAndEnable(
    userId: string,
    code: string,
    ip: string,
    userAgent: string,
    context: 'dashboard' | 'platform' = 'dashboard',
    tenantId?: string
  ): Promise<void> {
    this.assertPlaneTenant(context, tenantId)
    if (context === 'platform' && !this.platformUserRepo) {
      // See setup() — same misconfiguration guard, same rationale.
      throw new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)
    }

    // Fetch once at entry — used for mfaEnabled guard, email notification, and hook.
    const user = await this.fetchUserForContext(context, userId, tenantId)
    if (user.mfaEnabled) throw new AuthException(AUTH_ERROR_CODES.MFA_ALREADY_ENABLED)

    const setupKey = `mfa_setup:${hmacSha256(userSubject(context, userId, tenantId), this.options.hmacKey)}`
    const raw = await this.redis.get(setupKey)
    if (raw === null) throw new AuthException(AUTH_ERROR_CODES.MFA_SETUP_REQUIRED)

    const data = this.parseSetupData(raw, userId)
    const secretBase32 = this.decryptSecret(data.encryptedSecret)

    const totpWindow = this.mfaOptions.totpWindow
    // Use anti-replay even on MFA enable to prevent a racing/intercepted code
    // from being reused via the challenge endpoint within the acceptance window.
    const codeValid = await this.verifyTotpWithAntiReplay(
      context,
      userId,
      secretBase32,
      code,
      totpWindow,
      tenantId
    )
    if (!codeValid) {
      this.logger.warn(`verifyAndEnable: invalid TOTP code userId=${logSafe(userId)}`)
      throw new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE)
    }

    // Atomic completion gate: GETDEL returns the stored value and deletes the key
    // in one round-trip. Only the first concurrent caller observes a non-null
    // value and proceeds to the DB write + email. Any racing request that arrived
    // with the same valid TOTP code sees `null` and is treated as MFA_SETUP_REQUIRED,
    // preventing duplicate `updateMfa` writes and duplicate enablement emails.
    const consumed = await this.redis.getdel(setupKey)
    if (consumed === null) {
      this.logger.warn(
        `verifyAndEnable: setup key consumed by concurrent request userId=${logSafe(userId)}`
      )
      throw new AuthException(AUTH_ERROR_CODES.MFA_SETUP_REQUIRED)
    }

    // Serialized against every other MFA transition. The `getdel` above already makes the
    // enable single-shot among concurrent verify calls; this puts it in the same queue as
    // `disable` and the challenge splice, which write the same three fields.
    await this.transitionMfaRecord(context, userId, tenantId, () => ({
      mfaEnabled: true,
      mfaSecret: data.encryptedSecret,
      mfaRecoveryCodes: data.hashedCodes
    }))

    // Atomically invalidate all existing refresh sessions so the user must re-login
    // with the MFA challenge, then advance the token epoch so outstanding ACCESS tokens die
    // too. Every token issued before this moment is stamped `mfaEnabled: false`, and the MFA
    // gate refuses only `mfaEnabled && !mfaVerified` — so without the bump, a stolen access
    // token keeps clearing every MFA-gated route for its remaining lifetime, at the exact
    // moment the user enabled a second factor because they suspected that theft.
    // Scoped to the caller's own plane: the two id spaces come from different repositories
    // and may collide, so an unscoped revoke would log out the unrelated account sharing it.
    await this.redis.invalidateUserSessions(userId, tenantId, context)
    await this.redis.bumpUserTokenEpoch(userId, tenantId, context)

    this.logger.log(`verifyAndEnable: MFA enabled userId=${logSafe(userId)} context=${context}`)
    this.notify('verifyAndEnable', userId, user, (provider, tenant, email) =>
      provider.sendMfaEnabledNotification(tenant, email)
    )

    // Fire-and-forget hook — errors must not roll back a completed DB operation.
    if (this.hooks.afterMfaEnabled) {
      const safeUser =
        context === 'platform'
          ? this.platformUserAsSafeUser(user as AuthPlatformUser)
          : this.toSafeUser(user as AuthUser)
      void Promise.resolve(
        this.hooks.afterMfaEnabled(safeUser, {
          userId,
          ip,
          userAgent,
          sanitizedHeaders: {}
        })
      ).catch(() => undefined)
    }
  }

  // ---------------------------------------------------------------------------
  // challenge — MFA temp token exchange for full auth tokens (TOTP or recovery code)
  // ---------------------------------------------------------------------------

  /**
   * Validates a TOTP or recovery code and exchanges the MFA temp token for full
   * access tokens.
   *
   * Handles both `'dashboard'` and `'platform'` contexts. Applies brute-force
   * protection per-user. TOTP codes include anti-replay protection via a short-lived
   * Redis key keyed on an HMAC of the code and user ID.
   *
   * @param mfaTempToken - Short-lived MFA challenge JWT issued at login.
   * @param code - 6-digit TOTP code or `dddd-dddd-dddd` recovery code.
   * @param ip - Client IP address for session audit.
   * @param userAgent - User-Agent header for session description.
   * @returns `AuthResult` for dashboard context, `PlatformAuthResult` for platform context.
   * @throws `MFA_TEMP_TOKEN_INVALID` if the token is invalid or already consumed.
   * @throws `ACCOUNT_LOCKED` if the brute-force threshold has been reached.
   * @throws `MFA_INVALID_CODE` if the submitted code is incorrect.
   */
  async challenge(
    mfaTempToken: string,
    code: string,
    ip: string,
    userAgent: string
  ): Promise<AuthResult | PlatformAuthResult> {
    // Step 1: Verify the MFA temp token. We DO NOT consume it here — the
    // token stays alive in Redis until the TOTP / recovery code passes,
    // so a single mistyped digit surfaces as `MFA_INVALID_CODE` (retryable)
    // instead of `MFA_TEMP_TOKEN_INVALID` (dead end). The brute-force
    // counter (Step 2) caps how many wrong codes can be tried under one
    // token. The token is consumed atomically in Step 5 once the code is
    // confirmed valid.
    const {
      userId,
      context,
      tenantId,
      jti: tempTokenJti
    } = await this.tokenManager.verifyMfaTempToken(mfaTempToken)

    // Step 2: Brute-force check. HMAC key prevents Redis key reversal.
    // The 'challenge:' prefix namespaces this counter away from the 'disable' counter —
    // preventing a pre-auth attacker (who only has a mfaTempToken) from exhausting the
    // lockout threshold and blocking the authenticated user's ability to call disable().
    // The context namespaces it away from the OTHER identity plane: the two id spaces come
    // from different consumer repositories and may collide, so a counter keyed on the id
    // alone lets either party exhaust — or clear — the other's lockout budget.
    if (await this.isMfaFlowLockedOut('challenge', context, userId, tenantId)) {
      this.logger.warn(`challenge: account locked userId=${logSafe(userId)}`)
      throw new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED)
    }

    // Step 3: Fetch user from the correct repository, tenant-scoped for a dashboard challenge
    // (the temp token guarantees the tenant is present) so status / secret / session all resolve
    // against the account the login authenticated, not a homonym in another tenant.
    const user = await this.fetchUserForContext(context, userId, tenantId)

    // The account status was re-checked by `fetchUserForContext` above. Login gated it before
    // issuing the temp token, but that token outlives the check by its whole TTL: an account
    // suspended in between would otherwise complete the challenge and receive a full session.
    // Revoking access must not depend on how far through the login the holder already was.
    // Running it before Step 4 also keeps a blocked account from spending the KDF — the
    // recovery-code path costs one derivation per stored code.

    if (!user.mfaEnabled || !user.mfaSecret) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)
    }

    // Step 4: Decrypt TOTP secret and validate the submitted code.
    const { secret: secretBase32, stale: encryptedUnderRetiredKey } = this.decryptWithRotation(
      user.mfaSecret
    )
    const isTotpCode = /^\d{6}$/.test(code)
    const totpWindow = this.mfaOptions.totpWindow
    // Stryker disable next-line BooleanLiteral: `codeValid` is unconditionally reassigned in both branches before it is ever read, so its initializer is irrelevant
    let codeValid = false
    let usedRecoveryIndex = -1

    if (isTotpCode) {
      codeValid = await this.verifyTotpWithAntiReplay(
        context,
        userId,
        secretBase32,
        code,
        totpWindow,
        tenantId
      )
    } else {
      // Stryker disable next-line ArrayDeclaration: equivalent — the fallback stands in for an
      // account with no stored codes, and any content it could hold fails the constant-time
      // comparison exactly as the empty array does.
      const recoveryCodes = user.mfaRecoveryCodes ?? []
      usedRecoveryIndex = await this.verifyRecoveryCode(code, recoveryCodes)
      codeValid =
        usedRecoveryIndex >= 0 && (await this.claimRecoveryCode(context, userId, code, tenantId))
    }

    if (!codeValid) {
      await this.recordMfaFlowFailure('challenge', context, userId, tenantId)
      this.logger.warn(`challenge: invalid MFA code userId=${logSafe(userId)} context=${context}`)
      // Keep the MFA temp token alive — the user can retry with the next
      // TOTP window or a different recovery code under the same token.
      // bruteForce.recordFailure will eventually surface `ACCOUNT_LOCKED`
      // if attempts keep failing.
      throw new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE)
    }

    await this.resetMfaFlowFailures('challenge', context, userId, tenantId)

    // Step 5a: consume the MFA temp token now that the code is confirmed valid — and the
    // consume must WIN. Two concurrent submissions both observe the marker and both delete
    // it; without gating on which delete actually removed it, both issue a full session. That
    // was previously reasoned about as "a benign duplicate for the same legitimate user", but
    // it is not benign on the recovery-code path: a recovery code's whole security model is
    // that it is single-use, and this is one code and one token minting two sessions. The
    // loser is reported as an invalid temp token, which is what it now is.
    if (!(await this.tokenManager.consumeMfaTempToken(tempTokenJti))) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
    }

    // Step 5b: Consume the used recovery code (branch on context to use the correct repo).
    if (usedRecoveryIndex >= 0) {
      // mfaRecoveryCodes is guaranteed non-empty here: verifyRecoveryCode only returns ≥ 0
      // when it found a match by iterating the array, so the array cannot be empty or undefined.
      const existingCodes =
        user.mfaRecoveryCodes ??
        /* istanbul ignore next -- verifyRecoveryCode returns ≥0 only after iterating a non-null array */
        // Stryker disable next-line ArrayDeclaration: unreachable — this branch is only taken
        // when `verifyRecoveryCode` matched a code inside an array it had to iterate first.
        []
      // Serialized, and spliced against the record as it stands INSIDE the lock rather than
      // the copy read at the top of this method. Splicing the stale copy is what let a
      // concurrent `regenerateRecoveryCodes` be rolled back wholesale and a completed
      // `disable` be undone — see `transitionMfaRecord`.
      await this.transitionMfaRecord(context, userId, tenantId, (current) => {
        // The account stopped having MFA while this challenge was in flight — a `disable`
        // that has already completed. Writing here would re-enable it with the pre-disable
        // secret, so the code is spent (its `rcu:` claim already stands) and nothing is
        // written back.
        if (!current.mfaEnabled) return null
        // Stryker disable next-line ArrayDeclaration: the fallback's CONTENTS are unobservable. It
        // stands in for "this account has no recovery codes", and the only thing done with the list
        // is `indexOf(spentDigest)` — a digest that cannot be in a list the account does not have,
        // so any placeholder yields the same -1 and the same early return
        const currentCodes = current.mfaRecoveryCodes ?? []
        // Re-locate the code in the CURRENT list: the index computed against the earlier read
        // may name a different code, or none, after a concurrent write.
        /* istanbul ignore next -- defensive `noUncheckedIndexedAccess` fallback, unreachable: `usedRecoveryIndex >= 0` only after `verifyRecoveryCode` matched a code inside this very array */
        // Stryker disable next-line StringLiteral: unreachable — the index came from a match found by iterating `existingCodes`, so the element always exists and the fallback's value can never be read
        const spentDigest = existingCodes[usedRecoveryIndex] ?? ''
        const liveIndex = currentCodes.indexOf(spentDigest)
        if (liveIndex < 0) return null
        const updatedCodes = [...currentCodes]
        updatedCodes.splice(liveIndex, 1)
        return {
          mfaEnabled: true,
          // Re-encrypted here when the secret opened under a retired key: the write is
          // already happening, so the rotation drains for free.
          mfaSecret: encryptedUnderRetiredKey
            ? this.encryptSecret(secretBase32)
            : current.mfaSecret,
          mfaRecoveryCodes: updatedCodes
        }
      })
    } else if (encryptedUnderRetiredKey) {
      // A TOTP challenge writes nothing on its own, so the re-encryption needs its own write.
      // Fire-and-forget: the challenge has already succeeded and the retired key still opens
      // the secret, so a failure costs the migration and nothing else.
      void this.reencryptSecret(
        userId,
        context,
        secretBase32,
        user.mfaRecoveryCodes ?? [],
        tenantId
      )
    }

    this.logger.log(`challenge: MFA challenge passed userId=${logSafe(userId)} context=${context}`)

    // Step 6: Issue full tokens with mfaVerified: true.
    if (context === 'dashboard') {
      const safeUser = this.toSafeUser(user as AuthUser)
      const result = await this.tokenManager.issueTokens(safeUser, ip, userAgent, {
        mfaVerified: true
      })

      // Track the session when sessions are enabled (enforces concurrent session limit).
      if (this.options.sessions.enabled) {
        await this.sessionService.createSession({
          userId: safeUser.id,
          tenantId: safeUser.tenantId,
          rawRefreshToken: result.rawRefreshToken,
          ip,
          userAgent
        })
      }

      if (this.hooks.afterLogin) {
        void Promise.resolve(
          this.hooks.afterLogin(safeUser, { userId, ip, userAgent, sanitizedHeaders: {} })
        ).catch(() => undefined)
      }

      return result
    }

    // Platform context — reuse the already-fetched user to avoid a TOCTOU double-read.
    // platformUserRepo presence was already validated in fetchUserForContext; this cast is safe.
    const platformUser = user as AuthPlatformUser
    const result = await this.tokenManager.issuePlatformTokens(
      this.toSafePlatformUser(platformUser),
      ip,
      userAgent,
      { mfaVerified: true }
    )

    if (this.hooks.afterLogin) {
      void Promise.resolve(
        this.hooks.afterLogin(this.platformUserAsSafeUser(platformUser), {
          userId,
          ip,
          userAgent,
          sanitizedHeaders: {}
        })
      ).catch(() => undefined)
    }

    return result
  }

  // ---------------------------------------------------------------------------
  // disable — TOTP-verified MFA deactivation with session invalidation
  // ---------------------------------------------------------------------------

  /**
   * Disables MFA on a user's account after verifying a current TOTP code.
   *
   * Only TOTP codes are accepted — recovery codes cannot disable MFA by design.
   * See {@link MfaDisableDto} for the rationale.
   *
   * Supports both dashboard users and platform administrators. The caller must
   * pass the correct `context` value derived from the authenticated JWT `type`
   * claim so the right repository is used.
   *
   * After disabling, all refresh sessions are atomically invalidated so that the
   * next rotation produces tokens with `mfaEnabled: false` and `mfaVerified: false`,
   * clearing any stale `mfaVerified: true` claims from previously issued access tokens.
   *
   * @param userId - Internal ID of the user disabling MFA.
   * @param code - 6-digit TOTP code from the authenticator app.
   * @param ip - Client IP address (forwarded to hooks).
   * @param userAgent - User-Agent header (forwarded to hooks).
   * @param context - Which repository to use: `'dashboard'` (default) or `'platform'`.
   * @throws `TOKEN_INVALID` if the user is not found.
   * @throws `MFA_NOT_ENABLED` if MFA is not currently active.
   * @throws `ACCOUNT_LOCKED` if the brute-force threshold has been reached.
   * @throws `MFA_INVALID_CODE` if the submitted TOTP code is incorrect.
   */
  async disable(
    userId: string,
    code: string,
    ip: string,
    userAgent: string,
    context: 'dashboard' | 'platform' = 'dashboard',
    tenantId?: string
  ): Promise<void> {
    this.assertPlaneTenant(context, tenantId)
    const user = await this.fetchUserForContext(context, userId, tenantId)
    if (!user.mfaEnabled) throw new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)

    // 'disable:' prefix namespaces this counter away from the 'challenge' counter —
    // preventing a pre-auth attacker from exhausting the lockout threshold via the
    // challenge endpoint and blocking the authenticated user from disabling MFA.
    if (await this.isMfaFlowLockedOut('disable', context, userId, tenantId)) {
      this.logger.warn(`disable: account locked userId=${logSafe(userId)} context=${context}`)
      throw new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED)
    }

    if (!user.mfaSecret) {
      // mfaEnabled is true but mfaSecret is absent — database inconsistency.
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    const secretBase32 = this.decryptSecret(user.mfaSecret)
    const totpWindow = this.mfaOptions.totpWindow

    const codeValid = await this.verifyTotpWithAntiReplay(
      context,
      userId,
      secretBase32,
      code,
      totpWindow,
      tenantId
    )
    if (!codeValid) {
      await this.recordMfaFlowFailure('disable', context, userId, tenantId)
      this.logger.warn(`disable: invalid MFA code userId=${logSafe(userId)} context=${context}`)
      throw new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE)
    }

    await this.resetMfaFlowFailures('disable', context, userId, tenantId)

    // Serialized against every other MFA transition, so a challenge that read the record a
    // moment earlier cannot splice `mfaEnabled: true` and the old secret back on top of this.
    await this.transitionMfaRecord(context, userId, tenantId, () => ({
      mfaEnabled: false,
      mfaSecret: null,
      mfaRecoveryCodes: null
    }))

    // Invalidate all sessions so subsequent rotations produce tokens with mfaEnabled: false,
    // and advance the token epoch so outstanding access tokens die with them — an auth-state
    // change revokes everything issued under the previous state, in both directions, the same
    // rule the password-reset flow already applies.
    // Scoped to the caller's own identity plane (see verifyAndEnable).
    await this.redis.invalidateUserSessions(userId, tenantId, context)
    await this.redis.bumpUserTokenEpoch(userId, tenantId, context)

    this.logger.log(`disable: MFA disabled userId=${logSafe(userId)} context=${context}`)
    this.notify('disable', userId, user, (provider, tenant, email) =>
      provider.sendMfaDisabledNotification(tenant, email)
    )

    const safeUser =
      context === 'platform'
        ? this.platformUserAsSafeUser(user as AuthPlatformUser)
        : this.toSafeUser(user as AuthUser)

    if (this.hooks.afterMfaDisabled) {
      void Promise.resolve(
        this.hooks.afterMfaDisabled(safeUser, {
          userId,
          ip,
          userAgent,
          sanitizedHeaders: {}
        })
      ).catch(() => undefined)
    }
  }

  // ---------------------------------------------------------------------------
  // resetMfa() — administrative removal of a second factor
  // ---------------------------------------------------------------------------

  /**
   * Removes a user's second factor without their TOTP code, for a support desk facing a user
   * who has lost their authenticator AND their recovery codes.
   *
   * Every self-service exit from MFA needs the factor itself: {@link disable} wants a valid
   * TOTP code, and the recovery codes want the codes. A user who has lost both is locked out
   * permanently, by the control that exists to protect them — ASVS v5 §6.1.1 asks for an
   * administrative path out for exactly that reason.
   *
   * **Authorising the caller is the consumer's job.** The library deliberately ships no route
   * for this, the same decision and for the same reason as {@link AuthService.unlockAccount}:
   * who may reset whom is a question only the host application can answer, and all 39 routes
   * this library does ship are scoped to the caller's own account.
   *
   * Idempotent: resetting an account that has no second factor is a no-op, so a support desk
   * retrying does not get an error for a job already done.
   *
   * Three things happen beyond clearing the record, and none of them are optional:
   *
   * - **Sessions are invalidated and the token epoch is bumped**, so access tokens carrying
   *   `mfaVerified: true` die with the factor rather than outliving it.
   * - **The user is notified**, through the same channel {@link disable} uses. An
   *   administrative reset that the account holder cannot see is an account-takeover path:
   *   an attacker who reaches the support desk removes the second factor silently. The
   *   notification is what makes it an event the owner can detect and dispute.
   * - **It is logged** under its own prefix, so an administrative removal is distinguishable
   *   from a user-initiated one in the library's own log.
   *
   * The `afterMfaDisabled` hook fires too, so consumer-side alerting keeps working. It is not
   * given a separate hook: the consumer is the one calling this method, so they already know
   * an administrative reset happened — the hook exists to tell them about the paths they do
   * not initiate.
   *
   * @param userId - Internal ID of the user whose second factor is being removed.
   * @param context - Which identity plane the user belongs to: `'dashboard'` (default) or
   *   `'platform'`. Must match the plane the account lives in, or the lookup misses.
   * @throws `TOKEN_INVALID` if no user with that ID exists in the given plane.
   */
  async resetMfa(
    userId: string,
    context: 'dashboard' | 'platform' = 'dashboard',
    tenantId?: string
  ): Promise<void> {
    this.assertPlaneTenant(context, tenantId)
    const user = await this.fetchUserForContext(context, userId, tenantId)

    if (!user.mfaEnabled) {
      this.logger.log(
        `resetMfa: no second factor to remove userId=${logSafe(userId)} context=${context}`
      )
      return
    }

    // Serialized against every other MFA transition, so a challenge that read the record a
    // moment earlier cannot splice `mfaEnabled: true` and the old secret back on top of this.
    await this.transitionMfaRecord(context, userId, tenantId, () => ({
      mfaEnabled: false,
      mfaSecret: null,
      mfaRecoveryCodes: null
    }))

    await this.redis.invalidateUserSessions(userId, tenantId, context)
    await this.redis.bumpUserTokenEpoch(userId, tenantId, context)

    this.logger.warn(
      `resetMfa: MFA removed administratively userId=${logSafe(userId)} context=${context}`
    )
    this.notify('resetMfa', userId, user, (provider, tenant, email) =>
      provider.sendMfaDisabledNotification(tenant, email)
    )

    const safeUser =
      context === 'platform'
        ? this.platformUserAsSafeUser(user as AuthPlatformUser)
        : this.toSafeUser(user as AuthUser)

    if (this.hooks.afterMfaDisabled) {
      void Promise.resolve(
        this.hooks.afterMfaDisabled(safeUser, {
          userId,
          // No request context: this call does not come from one. Empty rather than invented,
          // so a consumer logging the hook cannot mistake a placeholder for a real address.
          ip: '',
          userAgent: '',
          sanitizedHeaders: {}
        })
      ).catch(() => undefined)
    }
  }

  // ---------------------------------------------------------------------------
  // regenerateRecoveryCodes — rotate the recovery code set for an MFA-enabled user
  // ---------------------------------------------------------------------------

  /**
   * Regenerates the user's MFA recovery codes after verifying a current TOTP code.
   *
   * Mirrors {@link disable} in its security posture: only TOTP codes are accepted
   * (recovery codes cannot rotate themselves by design), the brute-force counter
   * is checked, and the regeneration is fired against the correct repository for
   * the supplied `context`. The TOTP secret on the user record is unchanged — only
   * the recovery code list is replaced.
   *
   * Returns the plain-text codes once. They are NOT persisted in plain form; only a
   * keyed HMAC-SHA-256 of each goes into the database. The caller is responsible for showing the
   * codes to the user exactly once and warning them to save them safely.
   *
   * @remarks
   * **Sessions are intentionally NOT invalidated after this call.** Unlike
   * {@link verifyAndEnable} (which flips `mfaEnabled` from `false` to `true`) and
   * {@link disable} (which flips it back to `false`), this method does not change
   * the verification credential — the TOTP secret stays the same and existing
   * `mfaVerified: true` access tokens remain valid. Invalidating sessions here
   * would force a redundant re-auth on every recovery-code rotation, which is a
   * routine hygiene action a user might perform several times over the lifetime
   * of an account.
   *
   * @param userId - Internal ID of the user rotating recovery codes.
   * @param totpCode - 6-digit TOTP code from the authenticator app.
   * @param ip - Client IP address (forwarded to hooks).
   * @param userAgent - User-Agent header (forwarded to hooks).
   * @param context - Which repository to use: `'dashboard'` (default) or `'platform'`.
   * @throws `TOKEN_INVALID` if the user is not found or `mfaSecret` is missing
   *   when `mfaEnabled` is `true` (database inconsistency).
   * @throws `MFA_NOT_ENABLED` if MFA is not currently active, or if
   *   `context === 'platform'` and the platform user repository was not
   *   configured at module registration.
   * @throws `ACCOUNT_LOCKED` if the brute-force threshold has been reached.
   * @throws `MFA_INVALID_CODE` if the submitted TOTP code is incorrect.
   * @returns The freshly generated plain-text recovery codes, one-time display.
   */
  async regenerateRecoveryCodes(
    userId: string,
    totpCode: string,
    ip: string,
    userAgent: string,
    context: 'dashboard' | 'platform' = 'dashboard',
    tenantId?: string
  ): Promise<{ recoveryCodes: string[] }> {
    this.assertPlaneTenant(context, tenantId)
    if (context === 'platform' && !this.platformUserRepo) {
      // See setup()/verifyAndEnable() — same misconfiguration guard.
      throw new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)
    }

    // Ordering rationale (mirrors disable(), differs from challenge()):
    //
    //   1. fetchUserForContext (DB read)
    //   2. mfaEnabled guard
    //   3. brute-force isLockedOut check
    //
    // challenge() runs brute-force FIRST because it is a PUBLIC endpoint —
    // an attacker who knows a userId can otherwise force a DB read per
    // request. regenerateRecoveryCodes and disable are AUTHENTICATED
    // endpoints behind a JWT guard; the bearer token already binds the
    // caller to a specific userId, so the brute-force counter exists for
    // throttling repeated TOTP guesses by the legitimate user (or someone
    // who stole their access token), not for blocking enumeration. A DB
    // read on every request from an already-authenticated session is
    // acceptable for that threat model. Future contributors: do NOT
    // "fix" this to match challenge() — the ordering is deliberate.
    const user = await this.fetchUserForContext(context, userId, tenantId)
    if (!user.mfaEnabled) throw new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)

    // Reuse the 'disable:' counter namespace — both flows are TOTP-gated MFA
    // changes from an authenticated user, so they share the same lockout pool.
    // The 'disable:' prefix already isolates this from the public 'challenge:'
    // counter exhaustion vector.
    if (await this.isMfaFlowLockedOut('disable', context, userId, tenantId)) {
      this.logger.warn(
        `regenerateRecoveryCodes: account locked userId=${logSafe(userId)} context=${context}`
      )
      throw new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED)
    }

    if (!user.mfaSecret) {
      // mfaEnabled is true but mfaSecret is absent — database inconsistency.
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    const secretBase32 = this.decryptSecret(user.mfaSecret)
    const totpWindow = this.mfaOptions.totpWindow

    const codeValid = await this.verifyTotpWithAntiReplay(
      context,
      userId,
      secretBase32,
      totpCode,
      totpWindow,
      tenantId
    )
    if (!codeValid) {
      await this.recordMfaFlowFailure('disable', context, userId, tenantId)
      this.logger.warn(
        `regenerateRecoveryCodes: invalid MFA code userId=${logSafe(userId)} context=${context}`
      )
      throw new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE)
    }

    await this.resetMfaFlowFailures('disable', context, userId, tenantId)

    // Generate a fresh code set using the existing helper — same entropy, same
    // formatting, same keyed-MAC digesting as the initial setup() path.
    const recoveryCount = this.mfaOptions.recoveryCodeCount ?? DEFAULT_RECOVERY_CODE_COUNT
    const { plainCodes, hashedCodes } = this.hashRecoveryCodes(recoveryCount)

    // Preserve the existing TOTP secret — only the recovery code list changes.
    //
    // Sessions are intentionally NOT invalidated after this write. The TOTP
    // secret on the user row is unchanged, so existing `mfaVerified: true`
    // access tokens continue to be valid against the same factor. Compare
    // verifyAndEnable() and disable(), which DO invalidate sessions because
    // they flip the `mfaEnabled` claim — the verification posture changes
    // and stale tokens would carry the wrong claim. Recovery-code rotation
    // is a hygiene action that does not change the auth posture, so forcing
    // a global re-login here would be punitive without security benefit.
    // Serialized against every other MFA transition. The doc above promises the prior set is
    // replaced wholesale so an old code can never coexist with the new one — which held only
    // until a challenge that had read the old list spliced it back after this write.
    const replaced = await this.transitionMfaRecord(context, userId, tenantId, (current) => {
      // MFA was disabled while the new codes were being derived. Writing them would re-enable
      // it with the pre-disable secret, so the caller is told the factor is gone instead.
      if (!current.mfaEnabled) return null
      return { mfaEnabled: true, mfaSecret: current.mfaSecret, mfaRecoveryCodes: hashedCodes }
    })
    if (!replaced) throw new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)

    this.logger.log(
      `regenerateRecoveryCodes: recovery codes regenerated userId=${logSafe(userId)} context=${context}`
    )

    // Fire-and-forget hook — errors must not undo a completed regeneration.
    if (this.hooks.afterMfaRecoveryCodesRegenerated) {
      const safeUser =
        context === 'platform'
          ? this.platformUserAsSafeUser(user as AuthPlatformUser)
          : this.toSafeUser(user as AuthUser)
      void Promise.resolve(
        this.hooks.afterMfaRecoveryCodesRegenerated(safeUser, {
          userId,
          ip,
          userAgent,
          sanitizedHeaders: {}
        })
      ).catch(() => undefined)
    }

    return { recoveryCodes: plainCodes }
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Verifies a TOTP code and enforces anti-replay within the validation window.
   *
   * Stores a Redis key `tu:{hmac}` where `hmac = hmacSha256("{userSubject}:{code}", hmacKey)` —
   * so the marker is scoped to the plane and, on the dashboard plane, to the tenant. A second
   * submission of the same code within the TTL is rejected as a replay. Binding the marker to
   * both the subject and the code value prevents code disclosure in Redis and cross-user,
   * cross-tenant and cross-plane replay alike.
   *
   * A second marker under the pre-scoping preimage `{context}:{userId}:{code}` is written and
   * required alongside it; see the call site for why both must be fresh during a rolling upgrade.
   *
   * @returns `true` if the code is valid and has not been replayed, `false` otherwise.
   */
  private async verifyTotpWithAntiReplay(
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
    // tenants' user `1` no longer share a marker, so one cannot burn the other's code.
    const ttl = totpAntiReplayTtlSeconds(window)
    const scopedReplayKey = `tu:${hmacSha256(`${userSubject(context, userId, tenantId)}:${code}`, this.options.hmacKey)}`
    const legacyReplayKey = `tu:${hmacSha256(`${context}:${userId}:${code}`, this.options.hmacKey)}`
    // Fresh only when unclaimed on BOTH keys: during the rolling upgrade an old pod claims only the
    // legacy key and a new pod only the scoped one, so consulting a single key would let the same
    // code pass once on each side. Setting both and requiring both new closes the replay across the
    // two code paths; a marker left by the losing conjunct expires on its own. On the platform
    // plane the two keys coincide — claiming the scoped one a second time would always read as a
    // replay and reject every code — so the legacy claim is skipped there.
    const scopedIsNew = await this.redis.setnx(scopedReplayKey, ttl)
    if (scopedReplayKey === legacyReplayKey) return scopedIsNew
    const legacyIsNew = await this.redis.setnx(legacyReplayKey, ttl)
    return scopedIsNew && legacyIsNew
  }

  /**
   * Requires the caller to re-prove the account password before a factor is changed.
   *
   * Counted like a login, and for the same reason. `login` refuses an account after N wrong
   * passwords; this door asks for the same secret and used to refuse nothing, so a caller
   * holding a stolen access token but not the password could guess it here indefinitely. The
   * only control left was the per-route IP limit, which a distributed caller sidesteps — and
   * winning the guess buys the whole account: enrol a factor, change the password, move the
   * address. A door that takes the password has to carry the password's lockout.
   *
   * The identifier is namespaced by flow and by plane. Sharing one counter with `login` would
   * let an authenticated caller lock the owner out of their own sign-in, and sharing it across
   * planes would let a dashboard user and a platform admin holding the same id exhaust each
   * other's budget — the same two reasons the challenge and disable counters are split.
   *
   * @param context - The authentication plane, part of the counter's key.
   * @param userId - The account being changed, part of the counter's key.
   * @param passwordHash - The account's stored hash, or `null` for an OAuth-only account.
   * @param password - The password the caller submitted, if any.
   * @throws {@link AuthException} `ACCOUNT_LOCKED` once the failure budget for this flow is
   *   spent, or `INVALID_CREDENTIALS` when the account has a password and the submitted one is
   *   absent or wrong. The latter is deliberately the same code a failed login returns: an
   *   attacker holding a stolen token learns nothing from it beyond what they already knew.
   */
  private async assertReauthenticated(
    context: 'dashboard' | 'platform',
    userId: string,
    passwordHash: string | null,
    password: string | undefined,
    tenantId: string | undefined
  ): Promise<void> {
    if (passwordHash === null) {
      // No local password to re-prove — the account was provisioned through OAuth and its
      // credential belongs to the provider, which this library cannot verify inline. So the
      // proof is temporal instead of cryptographic: the caller must have completed a REAL
      // authentication within the last few minutes.
      //
      // This branch used to return, and that was the single worst thing in the library. An
      // access token lifted by XSS or from a shared machine was enough to enrol a factor the
      // ATTACKER holds; the enable then invalidates every session and bumps the epoch, so the
      // owner — who still signs in with Google perfectly well — is stopped at a challenge they
      // cannot pass, with the recovery codes having been displayed once, to the attacker. And
      // there was no way back: `disable` and `regenerateRecoveryCodes` both demand a live TOTP
      // code, and the reset flow refuses an account with no password. A fifteen-minute token
      // theft became permanent, unrecoverable loss of the account.
      //
      // The marker is written by `TokenManagerService.issueTokens` and NOT by `reissueTokens`,
      // which is what makes it proof of anything: an attacker holding a stolen session can
      // rotate it indefinitely and never make the mark fresh again. Producing one requires
      // driving a real sign-in, which requires the provider credentials the theft did not
      // include.
      const recent = await this.redis.get(
        recentAuthKey(context, userId, this.options.hmacKey, tenantId)
      )
      if (recent === null) {
        this.logger.warn(
          `reauthenticate: no recent authentication userId=${logSafe(userId)} context=${context}`
        )
        throw new AuthException(AUTH_ERROR_CODES.REAUTHENTICATION_REQUIRED)
      }
      return
    }

    if (await this.isMfaFlowLockedOut('reauth', context, userId, tenantId)) {
      this.logger.warn(
        `reauthenticate: account locked userId=${logSafe(userId)} context=${context}`
      )
      throw new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED)
    }

    // A missing password still pays the KDF, so "no password sent" and "wrong password" take
    // the same time — otherwise the response separates them for free.
    const supplied = password ?? ''
    const matches = await this.passwordService.compare(supplied, passwordHash)
    if (!matches) {
      await this.recordMfaFlowFailure('reauth', context, userId, tenantId)
      throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    }

    await this.resetMfaFlowFailures('reauth', context, userId, tenantId)
  }

  /**
   * Asserts a dashboard-plane call carries a tenant, narrowing it to `string` for the caller.
   *
   * This is the dashboard half of {@link assertPlaneTenant}, split out for one reason: an
   * assertion signature is the only way to state "past this point the tenant is present" to the
   * type system. `IUserRepository.findById` requires the tenant, and the account read behind the
   * MFA flows sits under a `context === 'dashboard'` branch where a `void` guard run earlier in
   * the caller has narrowed nothing. Without this the branch had to pass `string | undefined`
   * into a `string` parameter, which is precisely the tenant-blind read the guard exists to stop.
   *
   * @param tenantId - The tenant supplied by the caller, if any.
   * @throws {@link AuthException} `VALIDATION` (400) when it is missing or blank.
   */
  private assertDashboardTenant(tenantId: string | undefined): asserts tenantId is string {
    if (tenantId === undefined || tenantId === '') {
      // A dashboard call needs a non-EMPTY tenant, not merely a present one: a blank tenant builds
      // `dashboard:0::{userId}`, a third keyspace distinct from every real tenant's — and an empty
      // string is exactly what an unset environment variable becomes by the time it reaches this
      // call site.
      throw new AuthException(AUTH_ERROR_CODES.VALIDATION, [
        {
          field: 'tenantId',
          message: PLANE_TENANT_MESSAGE
        }
      ])
    }
  }

  /**
   * A dashboard MFA flow MUST carry the tenant it was authenticated in; a platform flow MUST NOT.
   *
   * The controller sources the tenant from the verified JWT, which always carries a validated
   * `tenantId`, so this never trips through the HTTP surface. It guards the OTHER caller:
   * `MfaService` is a public API, and a host wiring it directly — or a future SSO path — could hand
   * a dashboard `userId` with no tenant, which would silently reach the tenant-blind account read
   * and key derivation. Refuse it here, naming the field, rather than let it degrade to the
   * pre-tenant behaviour, which is exactly the fallback an attacker would aim for.
   *
   * @param context - The identity plane the call is on.
   * @param tenantId - The tenant supplied by the caller, if any.
   * @throws {@link AuthException} `VALIDATION` (400) when a dashboard call omits the tenant, or a
   *   platform call supplies one.
   */
  private assertPlaneTenant(context: 'dashboard' | 'platform', tenantId?: string): void {
    if (context === 'dashboard') {
      this.assertDashboardTenant(tenantId)
      return
    }
    if (tenantId !== undefined) {
      // The platform plane refuses any tenant at all, blank included: a platform admin is not
      // scoped to one, so a supplied tenant means the caller is on the wrong plane.
      throw new AuthException(AUTH_ERROR_CODES.VALIDATION, [
        {
          field: 'tenantId',
          message: PLANE_TENANT_MESSAGE
        }
      ])
    }
  }

  /**
   * The tenant-scoped brute-force identifier for one MFA flow, and the legacy plane-only one it
   * replaces — equal on the platform plane, where the subject never carried a tenant, and distinct
   * on the dashboard plane, where it now does.
   *
   * A rolling upgrade runs old and new code against one Redis at once: on the dashboard plane an
   * old pod counts a failure under `{flow}:{plane}:{userId}` while a new pod counts it under
   * `{flow}:{userSubject}`, and either alone leaves a hole — a lockout an old pod filled would not
   * stop a new pod, and a success on one would not clear the other. For one release every read
   * consults both and every write touches both, so the two move as one; a later release drops the
   * legacy arm. On the platform plane the two ids are identical (no tenant ever entered the
   * subject), so the legacy arm is skipped — operating it would just be the same key a second time,
   * double-counting a failure and locking a platform admin out at half the threshold. `{flow}`
   * (`challenge` / `disable` / `reauth`) keeps the three counters isolated, exactly as before.
   */
  private mfaFlowCounterIds(
    flow: 'challenge' | 'disable' | 'reauth',
    context: 'dashboard' | 'platform',
    userId: string,
    tenantId: string | undefined
  ): { legacy: string; scoped: string } {
    return {
      legacy: hmacSha256(`${flow}:${context}:${userId}`, this.options.hmacKey),
      scoped: hmacSha256(`${flow}:${userSubject(context, userId, tenantId)}`, this.options.hmacKey)
    }
  }

  /**
   * Locked out when EITHER the legacy or the tenant-scoped counter has reached the threshold, so
   * neither a lockout an old pod recorded nor one a new pod recorded can be bypassed mid-migration.
   */
  private async isMfaFlowLockedOut(
    flow: 'challenge' | 'disable' | 'reauth',
    context: 'dashboard' | 'platform',
    userId: string,
    tenantId: string | undefined
  ): Promise<boolean> {
    const { legacy, scoped } = this.mfaFlowCounterIds(flow, context, userId, tenantId)
    if (await this.bruteForce.isLockedOut(scoped)) return true
    return legacy !== scoped ? this.bruteForce.isLockedOut(legacy) : false
  }

  /**
   * Records the failure under both counters so the budget an attacker spends is seen by old and
   * new code alike — but under the scoped id ONCE when the two coincide (platform plane).
   */
  private async recordMfaFlowFailure(
    flow: 'challenge' | 'disable' | 'reauth',
    context: 'dashboard' | 'platform',
    userId: string,
    tenantId: string | undefined
  ): Promise<void> {
    const { legacy, scoped } = this.mfaFlowCounterIds(flow, context, userId, tenantId)
    await this.bruteForce.recordFailure(scoped)
    if (legacy !== scoped) await this.bruteForce.recordFailure(legacy)
  }

  /**
   * Clears both counters on success — resetting only one would leave the other to lock a
   * legitimately authenticated user out on the next attempt — collapsing to one when they coincide.
   */
  private async resetMfaFlowFailures(
    flow: 'challenge' | 'disable' | 'reauth',
    context: 'dashboard' | 'platform',
    userId: string,
    tenantId: string | undefined
  ): Promise<void> {
    const { legacy, scoped } = this.mfaFlowCounterIds(flow, context, userId, tenantId)
    await this.bruteForce.resetFailures(scoped)
    if (legacy !== scoped) await this.bruteForce.resetFailures(legacy)
  }

  /**
   * Sends an MFA state-change notice, fire-and-forget, with the recipient kept out of the log.
   *
   * **Not awaited, and that is the fix, not a shortcut.** These three sends used to be awaited
   * with no `catch`, so a rejected delivery travelled out of the service to `AuthExceptionFilter`
   * — which answered the caller with an error for an operation that had ALREADY completed. By
   * that point the secret is written, the sessions are invalidated and the token epoch is bumped;
   * the user's second factor is on, and telling them it failed is how they end up locked out of
   * an account they just secured. `PasswordResetService.notifyPasswordChanged` had reached the
   * same conclusion for the same reason.
   *
   * **And the address does not reach the log.** The filter logged that error raw, and an SMTP
   * rejection routinely NAMES the recipient it refused (`550 user@example.com: recipient
   * rejected`) — no quoted body required, which makes it the likeliest exposure of the set.
   * `describeChannelStatus` publishes nothing the channel wrote, and nothing parsed off it either,
   * so no part of that name comes through. `withheld` covers the fields this line composes rather than the error, and
   * `safeLogLine` checks the seam the template opens between them.
   *
   * @param origin - The calling flow, for the log line.
   * @param userId - Whose account changed.
   * @param user - The account, read for its tenant and address.
   * @param send - Which notice to dispatch.
   */
  private notify(
    origin: string,
    userId: string,
    user: AuthUser | AuthPlatformUser,
    send: (provider: IEmailProvider, tenantId: string, email: string) => Promise<void> | void
  ): void {
    const provider = this.emailProvider
    const tenantId = emailTenantOf(user)
    const email = user.email
    const withheld = [email]

    // An async IIFE rather than `Promise.resolve(send(...))`: the second evaluates the call before
    // the promise wraps it, so a provider that throws SYNCHRONOUSLY skips this handler entirely.
    // Inside the IIFE the call is still made synchronously and the `try` still catches the throw.
    //
    // Detached rather than awaited, and the trade is worth stating because the `catch` above means
    // awaiting would no longer fail the operation. What awaiting WOULD buy is that the handoff to
    // the channel completed before the caller was answered — which is not the same as the notice
    // arriving, and is bought with the user's request waiting on a third party after their MFA
    // state has already changed. A relay that is slow, not down, would then stall an enable that
    // has fully succeeded. Neither shape survives a freeze mid-flight: an awaited send loses the
    // notice AND the response. A guarantee that this notice is delivered belongs to a queue, which
    // is the consumer's `IEmailProvider` to provide and this library cannot supply on its behalf.
    void (async (): Promise<void> => {
      try {
        await send(provider, tenantId, email)
      } catch (err: unknown) {
        this.logger.error(
          safeLogLine(
            `${origin}: MFA notice delivery failed for user ${logSafe(userId)}: ` +
              describeChannelStatus(err),
            withheld
          )
        )
      }
    })()
  }

  /**
   * Fetches a user from the correct repository based on the MFA context, and refuses one whose
   * account is blocked.
   *
   * The status gate lives here rather than in each caller because every entry point that
   * reaches this method changes or spends an authentication factor, and every one of them
   * must refuse a suspended or banned account. It used to live in `challenge` alone, so
   * `setup`, `verifyAndEnable`, `disable` and `regenerateRecoveryCodes` had no gate at all:
   * an operator who suspended a compromised account bought nothing against an attacker still
   * holding an unexpired access token, who could turn the second factor off — or enrol their
   * own authenticator over it — for the token's remaining lifetime. Nothing else covers that
   * window: no status change bumps the token epoch, so the per-request check is the only
   * defence, and neither MFA controller composes `UserStatusGuard` (the platform plane has no
   * status guard at all). Every other authority-bearing route in the library does gate on
   * status; changing an authentication factor is at least as privileged as minting an
   * invitation.
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
  private async fetchUserForContext(
    context: 'dashboard' | 'platform',
    userId: string,
    tenantId?: string
  ): Promise<AuthUser | AuthPlatformUser> {
    if (context === 'dashboard') {
      this.assertDashboardTenant(tenantId)
      // Scoped to the tenant the caller was authenticated in — the JWT's `tenantId` on the
      // dashboard-authenticated flows, the challenge token's on the MFA challenge. A repository id
      // is unique only within a tenant, so an unscoped read could return, and this then decides
      // status / secret / session against, a homonym in another tenant. The assertion above is
      // what makes that a compile-time fact rather than a claim about the callers: the entry
      // points do all refuse a dashboard flow without a tenant, but a `void` guard narrows
      // nothing, so the read used to accept `string | undefined` on the strength of prose.
      const user = await this.userRepo.findById(userId, tenantId)
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
