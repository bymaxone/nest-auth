/**
 * @fileoverview Reads an option that holds `undefined` or `null` as unset, so that unset means the
 * default and never "no bound".
 *
 * A spread of the defaults and a user's group lets an own key holding `undefined` override the
 * default, and the validators treat `undefined` as unset and accept it, so a value such as
 * `Number(process.env.X) || undefined` would leave a cap with no bound. Each group is read once, by
 * property access, into a plain object without the keys that hold `undefined` or `null`, before
 * anything reads the options, so every validator and every merge sees the same thing. A typed
 * configuration class is read the same way as an object literal: its getters and its prototype are
 * read through the key lists below, and an own key the lists do not name is carried over.
 *
 * @layer Config
 */

import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

/** The shape of a key list the compiler checks is complete: every key of `T` and no other. */
type Keys<T> = Record<keyof T, true>

/** A group of the options, without the `undefined` an optional group carries. */
type Group<K extends keyof BymaxAuthModuleOptions> = NonNullable<BymaxAuthModuleOptions[K]>

/** Every key of the options. A key added to the interface and missing here fails to compile. */
const TOP_KEYS = {
  identifierKey: true,
  jwt: true,
  password: true,
  tokenDelivery: true,
  environment: true,
  secureCookies: true,
  cookies: true,
  rateLimit: true,
  mfa: true,
  sessions: true,
  bruteForce: true,
  passwordReset: true,
  emailVerification: true,
  platform: true,
  emailChange: true,
  invitations: true,
  apiKeys: true,
  roles: true,
  blockedStatuses: true,
  redisNamespace: true,
  oauth: true,
  workspaces: true,
  registration: true,
  routePrefix: true,
  tenantIdResolver: true,
  enforceTenantBinding: true,
  isTrustedProxy: true,
  controllers: true,
  userStatusCacheTtlSeconds: true
} satisfies Keys<BymaxAuthModuleOptions>

/**
 * The option groups whose keys are fixed settings, each with its keys. Only these are cleaned: a group
 * that is a host-defined map (`roles`, `oauth`) is left as given, because a `null` there is a mistake
 * to refuse, and a map this table does not name is untouched by construction.
 */
const GROUP_KEYS = {
  jwt: {
    secret: true,
    previousSecrets: true,
    accessExpiresIn: true,
    accessCookieMaxAgeMs: true,
    refreshExpiresInDays: true,
    absoluteSessionLifetimeDays: true,
    algorithm: true,
    issuer: true,
    audience: true,
    refreshGraceWindowSeconds: true
  } satisfies Keys<Group<'jwt'>>,
  password: {
    costFactor: true,
    minLength: true,
    blockSize: true,
    parallelization: true,
    blocklist: true
  } satisfies Keys<Group<'password'>>,
  cookies: {
    accessTokenName: true,
    refreshTokenName: true,
    sessionSignalName: true,
    refreshCookiePath: true,
    mfaTempCookiePath: true,
    resolveDomains: true,
    sameSite: true,
    trustedOrigins: true
  } satisfies Keys<Group<'cookies'>>,
  sessions: {
    enabled: true,
    defaultMaxSessions: true,
    maxSessionsResolver: true
  } satisfies Keys<Group<'sessions'>>,
  bruteForce: { maxAttempts: true, windowSeconds: true } satisfies Keys<Group<'bruteForce'>>,
  passwordReset: {
    method: true,
    tokenTtlSeconds: true,
    otpTtlSeconds: true,
    otpLength: true
  } satisfies Keys<Group<'passwordReset'>>,
  emailVerification: { required: true, otpTtlSeconds: true } satisfies Keys<
    Group<'emailVerification'>
  >,
  platform: { enabled: true } satisfies Keys<Group<'platform'>>,
  invitations: { enabled: true, tokenTtlSeconds: true } satisfies Keys<Group<'invitations'>>,
  emailChange: { tokenTtlSeconds: true } satisfies Keys<Group<'emailChange'>>,
  controllers: {
    auth: true,
    mfa: true,
    passwordReset: true,
    sessions: true,
    platform: true,
    oauth: true,
    invitations: true,
    emailChange: true,
    workspaces: true,
    workspaceInvitations: true
  } satisfies Keys<Group<'controllers'>>,
  rateLimit: { enabled: true, clientIpSource: true } satisfies Keys<Group<'rateLimit'>>,
  mfa: {
    encryptionKey: true,
    previousEncryptionKeys: true,
    issuer: true,
    recoveryCodeCount: true,
    totpWindow: true
  } satisfies Keys<Group<'mfa'>>,
  apiKeys: {
    enabled: true,
    pepper: true,
    scopes: true,
    header: true,
    prefix: true,
    lastUsedFlushSeconds: true,
    auditMode: true
  } satisfies Keys<Group<'apiKeys'>>,
  workspaces: {
    enabled: true,
    roles: true,
    permissions: true,
    allowCreate: true,
    maxWorkspacesPerUser: true,
    invitationTtlSeconds: true,
    maxPendingInvitationsPerWorkspace: true,
    membershipCacheTtlSeconds: true,
    deletionGraceDays: true,
    accessDeniedEvents: true,
    resolveRequestWorkspace: true,
    resolveWsWorkspace: true
  } satisfies Keys<Group<'workspaces'>>
}

/** The `workspaces` sub-groups that hold plain settings, each with its keys. */
const WORKSPACE_SUBGROUP_KEYS: Readonly<Record<string, readonly string[]>> = {
  accessDeniedEvents: ['max', 'windowSeconds']
}

/** Whether a value can be a group: an object, a class instance included, and not an array. */
function isObjectGroup(value: unknown): value is object {
  return Object(value) === value && typeof value !== 'function' && !Array.isArray(value)
}

/**
 * Reads a group by property access into a plain object, without the keys that hold `undefined` or
 * `null`. The listed keys are read through the property, so a getter on a class prototype counts; an
 * own enumerable key the list does not name is carried over, so a key this module does not know is kept.
 *
 * @param group - The group, of any prototype.
 * @param keys - The group's known keys.
 * @returns A plain object with the set keys.
 */
function readSetKeys(group: object, keys: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const key of new Set([...keys, ...Object.keys(group)])) {
    const entry: unknown = Reflect.get(group, key)
    if (entry !== undefined && entry !== null) out[key] = entry
  }
  return out
}

/**
 * Copies `value` without the keys that hold `undefined` or `null`, one level deep.
 *
 * @param value - A plain object, such as a message override.
 * @returns The object, with unset keys absent.
 */
export function dropUnsetKeys<T extends object>(value: T): T {
  const copy = { ...value }
  for (const [key, entry] of Object.entries(copy)) {
    if (entry === undefined || entry === null) Reflect.deleteProperty(copy, key)
  }
  return copy
}

/**
 * Returns the options as a plain object in which unset means absent: at the top level, inside each
 * fixed-key option group and inside the `workspaces` sub-groups that hold plain settings. The options,
 * and each group, may be an object literal, an object with no prototype, one from another realm, or a
 * class instance. Host-defined maps are left as given.
 *
 * @param options - The options as the host wrote them.
 * @returns A copy in which unset means absent.
 */
export function dropUnset(options: BymaxAuthModuleOptions): BymaxAuthModuleOptions {
  const copy = readSetKeys(options, Object.keys(TOP_KEYS))
  for (const [name, keys] of Object.entries(GROUP_KEYS)) {
    const entry = copy[name]
    if (!isObjectGroup(entry)) continue
    const group = readSetKeys(entry, Object.keys(keys))
    if (name === 'workspaces') {
      for (const [sub, subKeys] of Object.entries(WORKSPACE_SUBGROUP_KEYS)) {
        const inner = group[sub]
        if (isObjectGroup(inner)) group[sub] = readSetKeys(inner, subKeys)
      }
    }
    copy[name] = group
  }
  return Object.assign({} as BymaxAuthModuleOptions, copy)
}
