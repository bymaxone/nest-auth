/**
 * @fileoverview The boundary where the library reads what the host owns: the options it returns and the records
 * its repositories return.
 *
 * A host object can throw from any read (a getter, a Proxy, a revoked handle). The options are read once, inside
 * {@link readHostOptions}, and each record a repository returns is copied once, inside {@link guardRepository}, so
 * a failed read ends in the library's own error with the host's error as its `cause`, and the rest of the library
 * reads plain values.
 *
 * @layer Utility
 */

import { types } from 'node:util'

import { HttpException } from '@nestjs/common'
import type { Provider } from '@nestjs/common'

import {
  BYMAX_AUTH_API_KEY_REPOSITORY,
  GUARDED_API_KEY_REPOSITORY,
  GUARDED_MEMBERSHIP_REPOSITORY,
  GUARDED_PLATFORM_USER_REPOSITORY,
  GUARDED_USER_REPOSITORY,
  GUARDED_WORKSPACE_REPOSITORY,
  BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_USER_REPOSITORY,
  BYMAX_AUTH_WORKSPACE_REPOSITORY
} from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/** The most levels of nesting a record copy follows; a record deeper than this is not a record. */
const MAX_RECORD_DEPTH = 16

/**
 * Runs the reads of the host's options and ends a failure of the host's own in the library's configuration error.
 *
 * An error the library raised itself about a value it found (its message starts with `[BymaxAuthModule]`) goes out
 * as it is; anything else came from a getter or a Proxy of the host, and is reported without its text and with
 * itself as the cause.
 *
 * @param read - The reads of the options.
 * @returns What `read` returns.
 * @throws `Error` whose message starts with `[BymaxAuthModule]` and whose `cause` is the host's error.
 */
export function readHostOptions<T>(read: () => T): T {
  try {
    return read()
  } catch (error: unknown) {
    throw configurationError(error)
  }
}

/**
 * The same boundary for the factory that returns the options: its failure, the failure of the returned value to
 * resolve (a thenable whose `then` throws) and the reads of it all end in the configuration error.
 *
 * @param read - Calls the factory and awaits what it answers.
 * @returns A holder of what `read` resolves to: a promise resolved with a Proxy would read the Proxy's `then` once more,
 *   outside this boundary, so the value travels in a plain object.
 * @throws `Error` whose message starts with `[BymaxAuthModule]` and whose `cause` is the host's error.
 */
export async function readHostOptionsAsync<T>(
  read: () => Promise<T>
): Promise<{ readonly value: T }> {
  try {
    return { value: await read() }
  } catch (error: unknown) {
    throw configurationError(error)
  }
}

/**
 * Calls the host's options factory inside the same boundary as {@link readHostOptionsAsync}.
 *
 * @param factory - The host's `useFactory`.
 * @param args - What Nest injected into it.
 * @returns A holder of the options the factory answered.
 */
export function callFactory<T>(
  factory: (...args: never[]) => T | Promise<T>,
  args: unknown[]
): Promise<{ readonly value: T }> {
  return readHostOptionsAsync(async () => factory(...(args as never[])))
}

/** Whether the host's object holds the key, the read being inside the boundary of {@link readHostOptions}. */
export function hostHasKey(host: object, key: string): boolean {
  return readHostOptions(() => key in host)
}

/** The library's configuration error for a host failure; the library's own `[BymaxAuthModule]` errors pass through. */
function configurationError(error: unknown): Error {
  if (error instanceof Error && error.message.startsWith('[BymaxAuthModule]')) return error
  return new Error(
    '[BymaxAuthModule] the options could not be read: the factory, a getter or a Proxy of the host threw',
    { cause: error }
  )
}

/**
 * Every field the library reads by name from a record a repository returns: the fields of the user, platform user,
 * API key, workspace and membership interfaces. They are read by name after the object is enumerated, because an
 * object that answers by name and lists nothing (a lazy entity, a Proxy with only a `get`) cannot be copied by
 * listing it. A spec pins that the list covers every field of those interfaces.
 */
export const RECORD_FIELDS = [
  'createdAt',
  'deletionScheduledAt',
  'digest',
  'email',
  'emailVerified',
  'expiresAt',
  'id',
  'invitedByUserId',
  'label',
  'lastLoginAt',
  'lastUsedAt',
  'mfaEnabled',
  'mfaRecoveryCodes',
  'mfaSecret',
  'name',
  'oauthProvider',
  'oauthProviderId',
  'passwordHash',
  'platformId',
  'revokedAt',
  'role',
  'scopes',
  'status',
  'tenantId',
  'updatedAt',
  'userId',
  'workspace',
  'workspaceId'
] as const

/** The accessors a record inherits below the root prototype, which a spread would lose. Inherited data is not walked. */
function inheritedAccessors(value: object): string[] {
  const names: string[] = []
  for (
    let proto: object | null = Object.getPrototypeOf(value) as object | null;
    proto !== null && Object.getPrototypeOf(proto) !== null;
    proto = Object.getPrototypeOf(proto) as object | null
  ) {
    for (const name of Object.getOwnPropertyNames(proto)) {
      if (Object.getOwnPropertyDescriptor(proto, name)?.get !== undefined) names.push(name)
    }
  }
  return names
}

/** The checks for the values a record may hold that are not data to copy: a copy of them would not be them. */
const OPAQUE: readonly ((value: unknown) => boolean)[] = [
  types.isMap,
  types.isSet,
  types.isWeakMap,
  types.isWeakSet,
  types.isPromise,
  types.isRegExp,
  types.isNativeError,
  types.isAnyArrayBuffer,
  ArrayBuffer.isView,
  (value): boolean => value instanceof URL
]

/** Whether a value is one of the {@link OPAQUE} kinds, and is passed on as it is. The checks hold across realms. */
function isOpaque(value: object): boolean {
  return OPAQUE.some((check) => check(value))
}

/** A plain copy of a record: its own fields and inherited accessors, arrays and dates copied, the rest by reference. */
function copyValue(value: unknown, seen: WeakMap<object, unknown>, depth: number): unknown {
  if (value === null || typeof value !== 'object') return value
  if (depth > MAX_RECORD_DEPTH) throw new Error('the record nests deeper than the library follows')
  const known = seen.get(value)
  if (known !== undefined) return known
  if (types.isDate(value)) return new Date(value.getTime())
  if (Array.isArray(value)) {
    const copy: unknown[] = []
    seen.set(value, copy)
    for (let index = 0; index < value.length; index += 1)
      copy.push(copyValue(value[index], seen, depth + 1))
    return copy
  }
  if (isOpaque(value)) return value
  const copy: Record<string, unknown> = {}
  seen.set(value, copy)
  const source = value as Record<string, unknown>
  for (const key of new Set([...Object.getOwnPropertyNames(value), ...inheritedAccessors(value)])) {
    const copied = copyValue(source[key], seen, depth + 1)
    // A key named `__proto__` (what `JSON.parse` of user input produces) is data; assigning it would swap the prototype.
    if (key === '__proto__') {
      Object.defineProperty(copy, key, {
        value: copied,
        enumerable: true,
        writable: true,
        configurable: true
      })
    } else copy[key] = copied
  }
  for (const key of RECORD_FIELDS) {
    if (Object.hasOwn(copy, key)) continue
    const read = source[key]
    if (read !== undefined && typeof read !== 'function')
      copy[key] = copyValue(read, seen, depth + 1)
  }
  return copy
}

/**
 * Copies a record a repository returned, so a failed read of it ends here.
 *
 * @param record - What the repository returned.
 * @returns A plain copy, or `record` itself when it is not an object.
 * @throws {@link AuthException} `INTERNAL` whose `cause` is the host's error.
 */
export function copyHostRecord(record: unknown): unknown {
  try {
    return copyValue(record, new WeakMap(), 0)
  } catch (error: unknown) {
    throw new AuthException(AUTH_ERROR_CODES.INTERNAL, undefined, { cause: error })
  }
}

/** The lifecycle hooks of Nest, which the guarded view does not expose: the host's own provider receives them. */
const LIFECYCLE_HOOKS: ReadonlySet<PropertyKey> = new Set([
  'onModuleInit',
  'onApplicationBootstrap',
  'onModuleDestroy',
  'beforeApplicationShutdown',
  'onApplicationShutdown'
])

/**
 * Wraps a repository of the host so that every record it returns is copied once.
 *
 * @param host - The host's repository.
 * @returns A repository with the same methods, answering with plain copies.
 */
export function guardRepository<T extends object>(host: T): T {
  return new Proxy(host, {
    get(target, key): unknown {
      // Nest calls a lifecycle hook on every provider instance, and this view is a second one over the repository.
      if (LIFECYCLE_HOOKS.has(key)) return undefined
      let member: unknown
      try {
        member = Reflect.get(target, key, target)
      } catch (error: unknown) {
        // Awaiting the view reads `then`, and a symbol is no method name: neither may become a function that never settles.
        if (key === 'then' || typeof key === 'symbol') return undefined
        // The read happens in the service, outside any try, so the failure becomes the rejection of the call.
        return async (): Promise<never> => {
          throw new AuthException(AUTH_ERROR_CODES.INTERNAL, undefined, { cause: error })
        }
      }
      if (typeof member !== 'function') return member
      return async (...args: unknown[]): Promise<unknown> => {
        let answer: unknown
        try {
          answer = await (member as (...parameters: unknown[]) => unknown).apply(target, args)
        } catch (error: unknown) {
          // A typed error the host chose to throw (a unique-key conflict it maps to `AuthException`) goes out as it is.
          if (error instanceof HttpException) throw error
          throw new AuthException(AUTH_ERROR_CODES.INTERNAL, undefined, { cause: error })
        }
        return copyHostRecord(answer)
      }
    }
  })
}

/** The guarded token of each repository the host may provide, keyed by the host's token. */
const GUARDED_BY_HOST: ReadonlyMap<symbol, symbol> = new Map([
  [BYMAX_AUTH_USER_REPOSITORY, GUARDED_USER_REPOSITORY],
  [BYMAX_AUTH_PLATFORM_USER_REPOSITORY, GUARDED_PLATFORM_USER_REPOSITORY],
  [BYMAX_AUTH_API_KEY_REPOSITORY, GUARDED_API_KEY_REPOSITORY],
  [BYMAX_AUTH_WORKSPACE_REPOSITORY, GUARDED_WORKSPACE_REPOSITORY],
  [BYMAX_AUTH_MEMBERSHIP_REPOSITORY, GUARDED_MEMBERSHIP_REPOSITORY]
])

/**
 * The host's providers plus the guarded view of each repository among them, under the internal tokens the library's
 * services inject.
 *
 * The host's own providers are left exactly as they are, so the token the module exports still resolves to the
 * host's instance.
 *
 * @param providers - The host's `extraProviders`.
 * @returns The host's providers, then one guarded provider per repository the host supplied.
 */
export function withGuardedViews(providers: Provider[]): Provider[] {
  const views = [...GUARDED_BY_HOST]
    .filter(([host]) =>
      providers.some(
        (provider) =>
          typeof provider !== 'function' && 'provide' in provider && provider.provide === host
      )
    )
    .map(([host, guarded]) => ({
      provide: guarded,
      useFactory: (repository: object): object => guardRepository(repository),
      inject: [host]
    }))
  return [...providers, ...views]
}
