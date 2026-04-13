export type {
  DashboardJwtPayload,
  PlatformJwtPayload,
  MfaTempPayload
} from './jwt-payload.interface'
export type {
  AuthUser,
  SafeAuthUser,
  CreateUserData,
  UpdateMfaData,
  CreateWithOAuthData,
  IUserRepository
} from './user-repository.interface'
export type {
  AuthPlatformUser,
  SafeAuthPlatformUser,
  UpdatePlatformMfaData,
  IPlatformUserRepository
} from './platform-user-repository.interface'
export type { AuthResult, PlatformAuthResult, MfaChallengeResult } from './auth-result.interface'
export type {
  AuthenticatedRequest,
  PlatformAuthenticatedRequest
} from './authenticated-request.interface'
export type { OAuthProfile, OAuthProviderPlugin } from './oauth-provider.interface'
export type { SessionInfo, InviteData, IEmailProvider } from './email-provider.interface'
export type {
  HookContext,
  BeforeRegisterResult,
  OAuthLoginResult,
  IAuthHooks
} from './auth-hooks.interface'
export type {
  BymaxAuthModuleOptions,
  AuthModuleAsyncOptions
} from './auth-module-options.interface'
