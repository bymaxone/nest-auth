// @bymax-one/nest-auth — Server subpath public API

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

export { BymaxAuthModule } from './bymax-auth.module'

// ---------------------------------------------------------------------------
// Injection tokens
// ---------------------------------------------------------------------------

export {
  BYMAX_AUTH_BREACH_CHECKER,
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY
} from './bymax-auth.constants'

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export type { ResolvedOptions } from './config/resolved-options'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export { AUTH_THROTTLE_CONFIGS } from './constants/throttle-configs'

// ---------------------------------------------------------------------------
// Crypto utilities
// ---------------------------------------------------------------------------

export {
  decrypt,
  encrypt,
  generateSecureToken,
  hmacSha256,
  sha256,
  timingSafeCompare
} from './crypto'

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export { AUTH_ERROR_CODES, AUTH_ERROR_MESSAGES, AUTH_ERROR_STATUS } from './errors'

/**
 * The OpenAPI security-scheme NAMES, so a consumer never spells one as a string literal.
 *
 * A platform-only deployment guarding its own routes with `JwtAuthGuard` has to declare the
 * dashboard access scheme itself — `schemesFor` gates dashboard schemes on `dashboardMounted`,
 * so the fragment will not define one. Before this was exported the README told that consumer
 * to write `bymaxAuthAccessCookie` by hand, with nothing checking the spelling, in a section
 * whose whole subject is that literals drift from configuration.
 *
 * The names are stable identifiers — renaming one is a break a generated client feels — while
 * their DEFINITIONS are derived from configuration. That asymmetry is why the names are worth
 * exporting and the definitions are not.
 */
export { AUTH_SECURITY_SCHEMES } from './openapi/auth-openapi-fragment'

/**
 * The derivation itself, because exporting the names only narrows the problem above.
 *
 * A consumer reading a correct spelling off a constant still has to decide WHICH of the four
 * applies to their deployment, and that answer is not spelled anywhere they can reach — it takes
 * the guard family and `tokenDelivery` together, which is why every consumer setting a document
 * default was re-deriving it by reading this package's source. One of them derived it wrong and
 * their backend stopped booting when an environment variable changed.
 */
export { authDocumentSecurity } from './openapi/document-security'
export type {
  AuthDocumentSecurityParams,
  AuthGuardFamily,
  OpenApiSecurityRequirement
} from './openapi/document-security'
export type { AuthErrorCode } from './errors'
export { AuthException } from './errors'

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

export { NoOpAuthHooks } from './hooks/no-op-auth.hooks'

// ---------------------------------------------------------------------------
// Interfaces (types only — no runtime value)
// ---------------------------------------------------------------------------

export type {
  AuthenticatedRequest,
  PlatformAuthenticatedRequest
} from './interfaces/authenticated-request.interface'
export type {
  BeforeRegisterResult,
  HookContext,
  IAuthHooks,
  OAuthLoginResult
} from './interfaces/auth-hooks.interface'
export type {
  BymaxAuthModuleOptions,
  AuthModuleAsyncOptions,
  BymaxAuthRateLimitOptions,
  ClientIpSource
} from './interfaces/auth-module-options.interface'
export type {
  AuthResult,
  MfaChallengeResult,
  OAuthMfaChallengeResult,
  PlatformAuthResult,
  RotatedTokenResult
} from './interfaces/auth-result.interface'
export type { IEmailProvider, InviteData, SessionInfo } from './interfaces/email-provider.interface'
export type {
  DashboardJwtPayload,
  MfaTempPayload,
  PlatformJwtPayload
} from './interfaces/jwt-payload.interface'
export type { OAuthProfile, OAuthProviderPlugin } from './interfaces/oauth-provider.interface'
export type {
  AuthPlatformUser,
  IPlatformUserRepository,
  SafeAuthPlatformUser,
  UpdatePlatformMfaData
} from './interfaces/platform-user-repository.interface'
/**
 * The parameter shapes every tenant-scoped `IUserRepository` method takes.
 *
 * Exported because a consumer IMPLEMENTS this port and needs to name what it receives. They are
 * objects rather than positional strings for a reason the signature cannot show: TypeScript
 * accepts an implementation with fewer parameters, so a pre-upgrade `findById(id)` satisfied the
 * positional `findById(id, tenantId)` and ignored the tenant on a clean build — and a stale
 * `updatePassword(id, passwordHash)` bound the tenant id into the credential column. An object is
 * structurally incompatible with the old shape, so the same implementation now fails to compile.
 */
export type {
  AuthUser,
  CreateUserData,
  CreateWithOAuthData,
  FindUserByEmailParams,
  FindUserByOAuthIdParams,
  IUserRepository,
  LinkOAuthParams,
  SafeAuthUser,
  TenantScopedUserRef,
  UpdateEmailParams,
  UpdateEmailVerifiedParams,
  UpdateMfaData,
  UpdateMfaParams,
  UpdatePasswordParams,
  UpdateStatusParams
} from './interfaces/user-repository.interface'

// ---------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------

export { NoOpEmailProvider } from './providers/no-op-email.provider'
export { AUTH_EMAIL_KINDS, DefaultAuthEmailProvider } from './providers/default-auth-email.provider'
export type {
  AuthEmailSink,
  AuthEmailMessage,
  AuthEmailCatalogue,
  AuthEmailKind,
  DeliveryErrorPolicy,
  DeliveryErrorPolicyMap,
  DefaultAuthEmailProviderOptions
} from './providers/default-auth-email.provider'
export {
  CommonPasswordChecker,
  reduceToBaseWord
} from './providers/common-password-checker.provider'
export { AllowAllBreachChecker, HibpBreachChecker } from './providers/hibp-breach-checker.provider'

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

export { JwtAuthGuard } from './guards/jwt-auth.guard'
export { JwtPlatformGuard } from './guards/jwt-platform.guard'
export { MfaRequiredGuard } from './guards/mfa-required.guard'
export { OptionalAuthGuard } from './guards/optional-auth.guard'
export { PlatformRolesGuard } from './guards/platform-roles.guard'
export { RolesGuard } from './guards/roles.guard'
export { SelfOrAdminGuard } from './guards/self-or-admin.guard'
export { AuthRateLimitGuard } from './guards/auth-rate-limit.guard'
export { TrustedOriginGuard } from './guards/trusted-origin.guard'
export { UserStatusGuard } from './guards/user-status.guard'
export { WsJwtGuard } from './guards/ws-jwt.guard'

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

export { AuthExceptionFilter } from './filters/auth-exception.filter'
export { WsAuthExceptionFilter } from './filters/ws-auth-exception.filter'

// ---------------------------------------------------------------------------
// Pipes
// ---------------------------------------------------------------------------

export { createAuthValidationPipe } from './pipes/auth-validation.pipe'
export type { AuthFieldError } from './pipes/auth-validation.pipe'

// ---------------------------------------------------------------------------
// Decorators
// ---------------------------------------------------------------------------

export { CurrentUser } from './decorators/current-user.decorator'
export { PLATFORM_ROLES_KEY, PlatformRoles } from './decorators/platform-roles.decorator'
export { Authenticated } from './decorators/authenticated.decorator'
export { IS_PUBLIC_KEY, Public } from './decorators/public.decorator'
export { ROLES_KEY, Roles } from './decorators/roles.decorator'
export { SKIP_MFA_KEY, SkipMfa } from './decorators/skip-mfa.decorator'

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

export { AcceptInvitationDto } from './dto/accept-invitation.dto'
export { CreateInvitationDto } from './dto/create-invitation.dto'
export { ForgotPasswordDto } from './dto/forgot-password.dto'
export { LoginDto } from './dto/login.dto'
export { MfaChallengeDto } from './dto/mfa-challenge.dto'
export { MfaDisableDto } from './dto/mfa-disable.dto'
export { MfaRegenerateRecoveryCodesDto } from './dto/mfa-regenerate-recovery-codes.dto'
export { MfaVerifyDto } from './dto/mfa-verify.dto'
export { PlatformLoginDto } from './dto/platform-login.dto'
export { RegisterDto } from './dto/register.dto'
export { ResendOtpDto } from './dto/resend-otp.dto'
export { ResendVerificationDto } from './dto/resend-verification.dto'
export { ChangePasswordDto } from './dto/change-password.dto'
export { ResetPasswordDto } from './dto/reset-password.dto'
export { VerifyEmailDto } from './dto/verify-email.dto'
export { VerifyOtpDto } from './dto/verify-otp.dto'

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export { AuthService } from './services/auth.service'
/**
 * The shape {@link AuthService.revokeAllSessions} takes, for the same reason the `SessionService`
 * params types below are exported: a consumer calling it — a ban handler, an admin console — should
 * be able to name the object rather than assemble a literal and hope. Both fields are `string`, and
 * `revokeAllSessions(user.tenantId, user.id)` type checked against the old positional form, derived
 * an unrelated subject and returned normally: a "sign out everywhere" reported as done that revoked
 * nothing, or that revoked a colliding account in another tenant instead.
 */
export type { RevokeAllSessionsParams } from './services/auth.service'
// NOTE: `EmailChangeService` is only registered when `controllers.emailChange !== false`
// (the default). Importing it for a host module with the controller disabled causes an
// injection error — register it in `extraProviders` in that case.
export { EmailChangeService } from './services/email-change.service'
// `BruteForceService` is exported for consumers building their own lockout tooling. The
// administrative unlock itself lives on `AuthService.unlockAccount`, because the counter is
// keyed by an HMAC of `{tenantId}:{email}` under the library's own `hmacKey` — a key no
// consumer can derive, which made the lockout unclearable from outside until v1.0.12.
export { BruteForceService } from './services/brute-force.service'
// NOTE: MfaService is only registered in the NestJS container when
// controllers.mfa: true OR controllers.platform: true. Importing it here for
// use in a host-app module without those flags set will cause an injection error —
// register it in extraProviders in that case.
//
// `MfaService.resetMfa` is the administrative removal of a second factor, for a user who has
// lost both the authenticator and the recovery codes — every self-service exit needs the
// factor itself, so without it that user is locked out permanently by the control meant to
// protect them (ASVS v5 §6.1.1). Like `AuthService.unlockAccount`, it ships as a method and
// NOT as a route: every route this library exposes is scoped to the caller's own account, and
// who may reset whom is a decision only the host application can make.
export { MfaService } from './services/mfa.service'
export type { MfaSetupResult } from './services/mfa.service'
export { OtpService } from './services/otp.service'
// NOTE: `InvitationService` is only registered when `controllers.invitations` is enabled.
// Same caveat as the services above.
export { InvitationService } from './services/invitation.service'
// NOTE: PasswordResetService is only registered in the NestJS container when
// controllers.passwordReset !== false (the default). Importing it here for
// use in a host-app module where passwordReset is disabled will cause an
// injection error — register it in extraProviders in that case.
export { PasswordResetService } from './services/password-reset.service'
// NOTE: `PlatformAuthService` is only registered when `controllers.platform` is enabled.
// Same caveat as the services above. Exported because the platform identity surface has the
// same reason to be driven from consumer code the dashboard one does — a custom console
// route that issues an operator session without going through the bundled controller.
export { PlatformAuthService } from './services/platform-auth.service'
export { SessionService } from './services/session.service'
// Aliased to avoid collision with SessionInfo from email-provider.interface (which
// represents an email send session, not an auth session).
export type { SessionInfo as ActiveSessionInfo } from './services/session.service'

/**
 * The parameter objects of {@link SessionService}'s five entry points.
 *
 * Exported because a consumer building one — a scheduled sweep, an admin console — should be able
 * to name its shape rather than assemble an object literal and hope. Objects rather than
 * positional arguments because most of these fields are `string`: `listSessions(userId, hash)`
 * type checked against the old positional form and treated the hash as the tenant, returning an
 * empty listing indistinguishable from "this user has no sessions".
 */
export type {
  CreateSessionParams,
  ListSessionsParams,
  RevokeAllExceptCurrentParams,
  RevokeSessionParams
} from './services/session.service'
// `TokenDeliveryService` (v1.0.10+) is the only correct way to set the lib's
// auth cookies on a custom controller's response — replicating the cookie
// attributes inline would silently drift when the lib changes. Use it from
// consumer code that issues tokens via `AuthService.issueTokensForUserId`
// (or another password-less path) and needs to deliver them to the browser
// with the canonical attribute set.
export { TokenDeliveryService } from './services/token-delivery.service'
export { WsTicketService } from './services/ws-ticket.service'
export { AuthRevocationService } from './services/auth-revocation.service'
export type { RevocableTokenPayload } from './services/auth-revocation.service'
export { WS_TICKET_TTL_SECONDS } from './interfaces/ws-ticket.interface'
export type { WsTicketSnapshot } from './interfaces/ws-ticket.interface'
export type {
  BearerAuthResponse,
  BothAuthResponse,
  CookieAuthResponse,
  PlatformBearerAuthResponse
} from './services/token-delivery.service'
// NOTE: OAuthService is only registered in the NestJS container when
// controllers.oauth: true. Importing it here for use in a host-app module without
// that flag set will cause an injection error.
export { OAuthService } from './oauth/oauth.service'

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

export {
  describeChannelStatus,
  describeError,
  hasRole,
  redactSecrets,
  sanitizeHeaders,
  sleep
} from './utils'
export type { IPasswordBreachChecker } from './interfaces/password-breach-checker.interface'
export { AuthRateLimit } from './decorators/auth-rate-limit.decorator'
export type { AuthRateLimitWindow } from './decorators/auth-rate-limit.decorator'
