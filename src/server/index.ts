// @bymax-one/nest-auth — Server subpath public API

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

export { BymaxAuthModule } from './bymax-one-nest-auth.module'

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
} from './bymax-one-nest-auth.constants'

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
export { MfaRequiredGuard } from './guards/mfa-required.guard'
export { RolesGuard } from './guards/roles.guard'
export { UserStatusGuard } from './guards/user-status.guard'

// ---------------------------------------------------------------------------
// Decorators
// ---------------------------------------------------------------------------

export { CurrentUser } from './decorators/current-user.decorator'
export { IS_PUBLIC_KEY, Public } from './decorators/public.decorator'
export { ROLES_KEY, Roles } from './decorators/roles.decorator'
export { SKIP_MFA_KEY, SkipMfa } from './decorators/skip-mfa.decorator'

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

export { LoginDto } from './dto/login.dto'
export { MfaChallengeDto } from './dto/mfa-challenge.dto'
export { MfaDisableDto } from './dto/mfa-disable.dto'
export { MfaVerifyDto } from './dto/mfa-verify.dto'
export { RegisterDto } from './dto/register.dto'

// ---------------------------------------------------------------------------
// Services (Phase 2)
// ---------------------------------------------------------------------------

export { AuthService } from './services/auth.service'
export { MfaService } from './services/mfa.service'
export type { MfaSetupResult } from './services/mfa.service'
export { OtpService } from './services/otp.service'

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

export { hasRole, sanitizeHeaders, sleep } from './utils'
