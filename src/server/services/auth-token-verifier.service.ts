/**
 * @fileoverview The whole identity chain for an access token, in one call.
 *
 * @layer Service
 */

import { Inject, Injectable } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AccountStatusService } from './account-status.service'
import { AuthRevocationService } from './auth-revocation.service'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import {
  assertTokenType,
  assertValidJti,
  assertValidSub,
  assertValidTenantId
} from '../guards/utils/assert-token-type'
import type { DashboardJwtPayload, PlatformJwtPayload } from '../interfaces/jwt-payload.interface'
import { verifyWithRotation } from '../utils/verify-with-rotation'

/**
 * Which identity plane a caller expects a token to belong to.
 *
 * Always supplied by the caller and never inferred from the token's own `type` claim: inferring
 * would make the plane attacker-chosen, so a platform token would open a dashboard stream simply
 * by saying it is one.
 */
export type AuthPlane = 'dashboard' | 'platform'

/**
 * The outcome of a successful verification, discriminated by the plane so a caller can narrow to
 * the payload it actually got.
 *
 * `plane` is the same value the caller asked for — it is on the result because a consumer keying
 * live connections needs to record it, and because a tenant cannot answer the question: a platform
 * token carries no tenant claim at all.
 */
export type VerifiedAccessToken =
  | { readonly plane: 'dashboard'; readonly payload: DashboardJwtPayload }
  | { readonly plane: 'platform'; readonly payload: PlatformJwtPayload }

/**
 * What a verification checks beyond the signature.
 *
 * Both flags default to `true`. They exist to be turned OFF deliberately, by a caller that has
 * already established the same fact by another route — never as a way to make a reconnect cheaper.
 */
export interface VerifyAccessTokenOptions {
  /** The plane the caller expects. Required; see {@link AuthPlane}. */
  readonly plane: AuthPlane

  /**
   * Refuse a token whose account has MFA enabled but which was not itself issued after a
   * successful challenge — the rule {@link MfaRequiredGuard} applies to an HTTP route.
   *
   * It matters most on a reconnect: a refresh mints `mfaEnabled: true, mfaVerified: false`, so a
   * token that is otherwise entirely valid can represent a session that never completed its
   * second factor. The token's `type` does not imply it.
   *
   * @defaultValue true
   */
  readonly requireMfa?: boolean

  /**
   * Consult the account's CURRENT lifecycle status rather than the snapshot the token carries,
   * refusing a blocked, deleted or — on the dashboard plane, where verification gates API
   * access — unverified account.
   *
   * The only check here that reads a store other than Redis, and the only one that can answer
   * differently a second after the first call: a suspension lands between two reconnects.
   *
   * @defaultValue true
   */
  readonly checkStatus?: boolean
}

/**
 * Performs, in one call, every identity check a guarded HTTP route performs before a handler runs.
 *
 * A long-lived transport — a WebSocket, an SSE stream, a message consumer — has no guard in front
 * of it, so it has to establish the same facts itself, on a cadence, for as long as the connection
 * lives. Assembling that from the parts is where it goes wrong: {@link AuthRevocationService}
 * answers two channels and nothing else, and a bridge that calls it alone has verified a signature
 * and consulted a blacklist while checking neither the token's type, nor its `exp`, nor whether the
 * account behind it still exists.
 *
 * What one call establishes, in the order the refusals fire:
 *
 * 1. **Signature**, under the pinned algorithm and any secret retired by a rotation, plus the
 *    configured `issuer` and `audience` — all of `verifyWithRotation`.
 * 2. **Expiry.** `exp` is enforced by the same verification. It is worth naming separately because
 *    {@link AuthRevocationService.isAccessTokenRevoked} never reads it: a revocation check answers
 *    "was this withdrawn", not "is this still current".
 * 3. **Claim shape** — `jti` a UUID v4, `sub` and (on the dashboard plane) `tenantId` bounded
 *    non-empty strings. These become Redis keys downstream; a malformed one builds a key nobody
 *    intended.
 * 4. **Token type**, matched against the plane the caller named. Without it an `mfa_challenge`
 *    token — signed with the same secret, holding half a credential — reads as a valid session.
 * 5. **Revocation**, both channels: the per-token blacklist a logout writes and the per-user epoch
 *    a password reset or an administrative revoke-all advances.
 * 6. **MFA policy**, unless the caller opted out. See {@link VerifyAccessTokenOptions.requireMfa}.
 * 7. **Account status**, unless the caller opted out. See
 *    {@link VerifyAccessTokenOptions.checkStatus}.
 *
 * **What it still does not do, and cannot.** Route authorization is the consumer's — this answers
 * who the caller is, never what they may do, so a `@Roles()` equivalent stays yours to apply on
 * every message a stream carries, not only at the handshake. Tenant binding
 * (`enforceTenantBinding`) needs the request the resolver reads, which a redeemed ticket no longer
 * has. And nothing here holds a subscription: it answers at the moment it is called, so a stream
 * that calls it once at connect is authorized for the lifetime of the token, not of the session.
 * Call it again on a cadence, and treat a rejection as a disconnect.
 *
 * @example
 * ```ts
 * const { plane, payload } = await this.verifier.verifyAccessToken(token, { plane: 'dashboard' })
 * registry.add(socket, { plane, userId: payload.sub, tenantId: payload.tenantId })
 * ```
 *
 * @layer Service
 */
@Injectable()
export class AuthTokenVerifierService {
  /**
   * @param jwtService - The Nest JWT service, configured with the current signing secret.
   * @param options - Resolved module options, for the algorithm, the binding claims and the
   *   secrets retired by a rotation.
   * @param revocation - The two revocation channels, shared with the mounted guards.
   * @param accountStatus - The account lifecycle gate, shared with {@link UserStatusGuard}.
   */
  constructor(
    @Inject(JwtService) private readonly jwtService: JwtService,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(AuthRevocationService) private readonly revocation: AuthRevocationService,
    @Inject(AccountStatusService) private readonly accountStatus: AccountStatusService
  ) {}

  /**
   * Verifies an access token and returns its payload, or throws.
   *
   * Every refusal is an {@link AuthException}. The token-shaped ones all answer `TOKEN_INVALID`
   * rather than naming which check failed, matching the guards: telling a caller "valid but
   * revoked" apart from "never valid" is an oracle for no benefit. The two that DO name
   * themselves are the ones a legitimate client must act on differently — `MFA_REQUIRED` means
   * complete the challenge, and the `ACCOUNT_*` codes mean the account itself is refused.
   *
   * @param token - The compact JWT, exactly as presented. Never a decoded payload: a caller that
   *   already decoded it has skipped the signature, which is the check everything else rests on.
   * @param options - The plane, and which of the two optional checks to run.
   * @returns The verified payload, tagged with the plane it was checked against.
   * @throws {@link AuthException} with `TOKEN_INVALID` when the signature, expiry, claim shape,
   *   type or revocation state refuses the token; `MFA_REQUIRED` when the account has MFA enabled
   *   and this token predates its challenge; or the matching `ACCOUNT_*` / `EMAIL_NOT_VERIFIED`
   *   code when the account is no longer usable.
   */
  async verifyAccessToken(
    token: string,
    options: VerifyAccessTokenOptions
  ): Promise<VerifiedAccessToken> {
    const { plane, requireMfa = true, checkStatus = true } = options

    return plane === 'dashboard'
      ? await this.verifyDashboard(token, requireMfa, checkStatus)
      : await this.verifyPlatform(token, requireMfa, checkStatus)
  }

  /**
   * The dashboard arm: the full chain plus the tenant claim and the tenant-scoped status gate.
   *
   * @param token - The compact JWT.
   * @param requireMfa - Whether to apply the MFA policy.
   * @param checkStatus - Whether to consult the account's current status.
   * @returns The verified dashboard payload.
   * @throws {@link AuthException} as {@link verifyAccessToken} documents.
   */
  private async verifyDashboard(
    token: string,
    requireMfa: boolean,
    checkStatus: boolean
  ): Promise<VerifiedAccessToken> {
    const payload = this.verifySignature<DashboardJwtPayload>(token)

    assertValidJti(payload.jti)
    assertValidSub(payload.sub)
    // Only cast from the token, yet it drives every tenant-scoped key built below.
    assertValidTenantId(payload.tenantId)
    assertTokenType(payload, 'dashboard')

    if (await this.revocation.isAccessTokenRevoked(payload, 'dashboard')) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    if (requireMfa) this.assertMfaSatisfied(payload)

    if (checkStatus) {
      await this.accountStatus.assertDashboardAccountUsable({
        userId: payload.sub,
        tenantId: payload.tenantId
      })
    }

    return { plane: 'dashboard', payload }
  }

  /**
   * The platform arm. No tenant claim exists to assert or to scope by — a platform administrator
   * is cross-tenant, which is also why the revocation read is told which epoch namespace to use.
   *
   * @param token - The compact JWT.
   * @param requireMfa - Whether to apply the MFA policy.
   * @param checkStatus - Whether to consult the administrator's current status.
   * @returns The verified platform payload.
   * @throws {@link AuthException} as {@link verifyAccessToken} documents.
   */
  private async verifyPlatform(
    token: string,
    requireMfa: boolean,
    checkStatus: boolean
  ): Promise<VerifiedAccessToken> {
    const payload = this.verifySignature<PlatformJwtPayload>(token)

    assertValidJti(payload.jti)
    assertValidSub(payload.sub)
    assertTokenType(payload, 'platform')

    if (await this.revocation.isAccessTokenRevoked(payload, 'platform')) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    if (requireMfa) this.assertMfaSatisfied(payload)

    if (checkStatus) await this.accountStatus.assertPlatformAccountUsable(payload.sub)

    return { plane: 'platform', payload }
  }

  /**
   * Verifies signature, algorithm, binding claims and expiry, collapsing every failure to one
   * opaque refusal.
   *
   * @typeParam T - The payload shape the caller's plane expects.
   * @param token - The compact JWT.
   * @returns The decoded payload, cast to `T`. The claims are asserted by the caller.
   * @throws {@link AuthException} with `TOKEN_INVALID` when no configured secret accepts it.
   */
  private verifySignature<T extends object>(token: string): T {
    try {
      return verifyWithRotation<T>(this.jwtService, this.options, token)
    } catch {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
  }

  /**
   * Applies the MFA policy to an already-verified payload.
   *
   * The `typeof` arm is not defensive noise: the payload is cast from a token, so a signed token
   * that simply omits `mfaEnabled` would otherwise compare `undefined === true`, read as "MFA is
   * off" and pass a gate it was never shown to.
   *
   * @param payload - The verified payload, either plane.
   * @throws {@link AuthException} with `TOKEN_INVALID` when the claim is missing or not a
   *   boolean, or `MFA_REQUIRED` when MFA is enabled and this token predates the challenge.
   */
  private assertMfaSatisfied(payload: DashboardJwtPayload | PlatformJwtPayload): void {
    if (typeof payload.mfaEnabled !== 'boolean') {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
    if (payload.mfaEnabled && payload.mfaVerified !== true) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_REQUIRED)
    }
  }
}
