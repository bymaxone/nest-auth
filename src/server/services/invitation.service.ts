import { ForbiddenException, Inject, Injectable } from '@nestjs/common'

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
import { generateSecureToken, sha256 } from '../crypto/secure-token'
import type { AcceptInvitationDto } from '../dto/accept-invitation.dto'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { AuthResult } from '../interfaces/auth-result.interface'
import type { IEmailProvider } from '../interfaces/email-provider.interface'
import type { IUserRepository } from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
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
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  return (
    typeof v['email'] === 'string' &&
    typeof v['role'] === 'string' &&
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
 */
@Injectable()
export class InvitationService {
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
   * Authorization steps:
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
    const normalizedEmail = email.trim().toLowerCase()

    const hierarchy = this.options.roles.hierarchy

    // Validate that the requested role exists in the configured hierarchy.
    if (!Object.hasOwn(hierarchy, role)) {
      throw new ForbiddenException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE)
    }

    // Fetch the inviter to validate their role authorization.
    const inviter = await this.userRepo.findById(inviterUserId)
    if (!inviter) {
      // The JWT references a user that no longer exists — treat as an invalid token.
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    // The inviter must hold a role >= the role being invited.
    if (!hasRole(inviter.role, role, hierarchy)) {
      throw new ForbiddenException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE)
    }

    // Generate a cryptographically secure single-use token (64 hex chars).
    const rawToken = generateSecureToken(32)
    const tokenKey = `inv:${sha256(rawToken)}`
    const ttl = this.options.invitations.tokenTtlSeconds

    const stored: StoredInvitation = {
      email: normalizedEmail,
      role,
      tenantId,
      inviterUserId,
      createdAt: new Date().toISOString()
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
      throw new AuthException(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
    }

    if (!isStoredInvitation(parsed)) {
      throw new AuthException(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
    }

    const invitation = parsed

    // Re-validate role against the hierarchy to guard against Redis tampering.
    if (!Object.hasOwn(this.options.roles.hierarchy, invitation.role)) {
      throw new AuthException(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
    }

    // Guard against duplicate registrations within the same tenant.
    const existing = await this.userRepo.findByEmail(invitation.email, invitation.tenantId)
    if (existing) {
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS)
    }

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

    // Notify hooks — fire-and-forget; hook errors do not roll back account creation.
    await this.hooks.afterInvitationAccepted?.(safeUser, {
      ip,
      userAgent,
      sanitizedHeaders: sanitizeHeaders(headers)
    })

    return result
  }
}
