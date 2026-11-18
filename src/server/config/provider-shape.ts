/**
 * @fileoverview Boot-time check of the shape of the hooks and the email provider a host registers.
 *
 * A host supplies both as providers, and only a ready-made `useValue` object can be inspected before
 * the application is built: a class, a factory or an alias is given the benefit of the doubt, as it is
 * for the API-key audit hook. For an object that can be seen, each member the library calls by name
 * that is present must be a function, because a hook is called as `hooks.x?.(...)` and a value that
 * is neither nullish nor a function throws at the first event that fires it; the email provider must
 * also carry the methods the library calls without a guard. Any other member, such as a logger, a
 * client or a `from` address held by the object, is the host's and is not looked at.
 *
 * @layer Config
 */

import type { Provider } from '@nestjs/common'

import { describeReceived } from './describe-received'
import { validateControllerFlags } from './enum-boolean-options'
import { BYMAX_AUTH_EMAIL_PROVIDER, BYMAX_AUTH_HOOKS } from '../bymax-auth.constants'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { IEmailProvider } from '../interfaces/email-provider.interface'

/** The email methods the library calls with no guard, so a provider without one fails on that message. */
export const REQUIRED_EMAIL_METHODS: readonly string[] = [
  'sendPasswordResetToken',
  'sendPasswordResetOtp',
  'sendEmailVerificationOtp',
  'sendMfaEnabledNotification',
  'sendMfaDisabledNotification',
  'sendInvitation'
]

/** The `useValue` of the provider registered under `token`, when it is a ready-made value. */
function readyMadeValue(providers: Provider[], token: symbol): { found: boolean; value: unknown } {
  const entry = providers.find(
    (p) => typeof p !== 'function' && 'provide' in p && p.provide === token
  )
  if (entry === undefined || !('useValue' in entry)) return { found: false, value: undefined }
  return { found: true, value: entry.useValue }
}

/** Every hook the library calls by name; a hook added to `IAuthHooks` and missing here fails to compile. */
const HOOK_NAMES = Object.keys({
  beforeRegister: true,
  afterRegister: true,
  beforeLogin: true,
  afterLogin: true,
  afterLogout: true,
  afterPlatformLogout: true,
  onLoginFailed: true,
  onLockout: true,
  onRefreshTokenReuseDetected: true,
  afterMfaEnabled: true,
  afterMfaDisabled: true,
  afterMfaRecoveryCodesRegenerated: true,
  onNewSession: true,
  afterEmailVerified: true,
  afterPasswordReset: true,
  onOAuthLogin: true,
  afterInvitationAccepted: true,
  onSessionEvicted: true,
  onApiKeyRequest: true,
  beforeWorkspaceCreate: true,
  onWorkspaceEvent: true
} satisfies Record<keyof IAuthHooks, true>)

/** Every email method the library calls by name, with the same compile-time completeness check. */
const EMAIL_METHOD_NAMES = Object.keys({
  sendPasswordResetToken: true,
  sendPasswordResetOtp: true,
  sendEmailVerificationOtp: true,
  sendPasswordChangedNotification: true,
  sendEmailChangeVerification: true,
  sendEmailChangedNotification: true,
  sendMfaEnabledNotification: true,
  sendMfaDisabledNotification: true,
  sendNewSessionAlert: true,
  sendInvitation: true,
  sendWorkspaceInvitation: true
} satisfies Record<keyof IEmailProvider, true>)

/**
 * Refuses a ready-made value that is not an object, or whose named member is present and is not a
 * function. A nullish member is absent, as the optional call treats it.
 *
 * @param label - The provider, for the message.
 * @param value - The `useValue`.
 * @param names - The members the library calls by name.
 */
function assertNamedFunctions(
  label: string,
  value: unknown,
  names: readonly string[]
): asserts value is object {
  if (typeof value !== 'object' || value === null) {
    throw new Error(
      `[BymaxAuthModule] ${label} must be an object (received ${describeReceived(value)}).`
    )
  }
  for (const name of names) {
    const member: unknown = Reflect.get(value, name)
    if (member !== undefined && member !== null && typeof member !== 'function') {
      throw new Error(
        `[BymaxAuthModule] ${label}.${name} must be a function (received ${describeReceived(member)}).`
      )
    }
  }
}

/**
 * Checks the hooks and the email provider when they are registered as ready-made values.
 *
 * @param providers - The host's `extraProviders`.
 * @throws {Error} naming the provider and the member that is not usable.
 */
export function assertProviderShapes(providers: Provider[]): void {
  const hooks = readyMadeValue(providers, BYMAX_AUTH_HOOKS)
  if (hooks.found && hooks.value !== null && hooks.value !== undefined) {
    assertNamedFunctions('BYMAX_AUTH_HOOKS', hooks.value, HOOK_NAMES)
  }

  const email = readyMadeValue(providers, BYMAX_AUTH_EMAIL_PROVIDER)
  if (!email.found) return
  assertNamedFunctions('BYMAX_AUTH_EMAIL_PROVIDER', email.value, EMAIL_METHOD_NAMES)
  for (const name of REQUIRED_EMAIL_METHODS) {
    if (typeof Reflect.get(email.value, name) !== 'function') {
      throw new Error(
        `[BymaxAuthModule] BYMAX_AUTH_EMAIL_PROVIDER.${name} is required and must be a function.`
      )
    }
  }
}

/**
 * Checks what `registerAsync` is handed before it builds anything: the controller flags, and the
 * shape of the hooks and the email provider.
 *
 * @param controllers - The host's `controllers`, if any.
 * @param providers - The host's `extraProviders`.
 * @throws {Error} naming the option or provider member that is not usable.
 */
export function validateRegistrationShapes(controllers: unknown, providers: Provider[]): void {
  validateControllerFlags(controllers)
  assertProviderShapes(providers)
}
