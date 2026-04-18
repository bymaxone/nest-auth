// @bymax-one/nest-auth — Server subpath public API

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

export { BymaxAuthModule } from './bymax-auth.module'

// ---------------------------------------------------------------------------
// Injection tokens
// ---------------------------------------------------------------------------

export {
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

export { AUTH_ERROR_CODES, AUTH_ERROR_MESSAGES } from './errors'
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
  AuthModuleAsyncOptions
} from './interfaces/auth-module-options.interface'
export type {
  AuthResult,
  MfaChallengeResult,
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
export type {
  AuthUser,
  CreateUserData,
  CreateWithOAuthData,
  IUserRepository,
  SafeAuthUser,
  UpdateMfaData
} from './interfaces/user-repository.interface'

// ---------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------

export { NoOpEmailProvider } from './providers/no-op-email.provider'

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
export { UserStatusGuard } from './guards/user-status.guard'
export { WsJwtGuard } from './guards/ws-jwt.guard'

// ---------------------------------------------------------------------------
// Decorators
// ---------------------------------------------------------------------------

export { CurrentUser } from './decorators/current-user.decorator'
export { PLATFORM_ROLES_KEY, PlatformRoles } from './decorators/platform-roles.decorator'
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
export { MfaVerifyDto } from './dto/mfa-verify.dto'
export { PlatformLoginDto } from './dto/platform-login.dto'
export { RegisterDto } from './dto/register.dto'
export { ResendOtpDto } from './dto/resend-otp.dto'
export { ResendVerificationDto } from './dto/resend-verification.dto'
export { ResetPasswordDto } from './dto/reset-password.dto'
export { VerifyEmailDto } from './dto/verify-email.dto'
export { VerifyOtpDto } from './dto/verify-otp.dto'

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export { AuthService } from './services/auth.service'
// NOTE: MfaService is only registered in the NestJS container when
// controllers.mfa: true OR controllers.platform: true. Importing it here for
// use in a host-app module without those flags set will cause an injection error —
// register it in extraProviders in that case.
export { MfaService } from './services/mfa.service'
export type { MfaSetupResult } from './services/mfa.service'
export { OtpService } from './services/otp.service'
// NOTE: PasswordResetService is only registered in the NestJS container when
// controllers.passwordReset !== false (the default). Importing it here for
// use in a host-app module where passwordReset is disabled will cause an
// injection error — register it in extraProviders in that case.
export { PasswordResetService } from './services/password-reset.service'
export { SessionService } from './services/session.service'
// Aliased to avoid collision with SessionInfo from email-provider.interface (which
// represents an email send session, not an auth session).
export type { SessionInfo as ActiveSessionInfo } from './services/session.service'
// NOTE: OAuthService is only registered in the NestJS container when
// controllers.oauth: true. Importing it here for use in a host-app module without
// that flag set will cause an injection error.
export { OAuthService } from './oauth/oauth.service'

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

export { hasRole, sanitizeHeaders, sleep } from './utils'
