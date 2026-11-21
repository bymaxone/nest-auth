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

/** The names a record exposes through the prototype chain below `Object.prototype`, which a spread would lose. */
function inheritedAccessors(value: object): string[] {
  const names: string[] = []
  for (
    let proto: object | null = Object.getPrototypeOf(value) as object | null;
    proto !== null && proto !== Object.prototype;
    proto = Object.getPrototypeOf(proto) as object | null
  ) {
    for (const name of Object.getOwnPropertyNames(proto)) {
      if (Object.getOwnPropertyDescriptor(proto, name)?.get !== undefined) names.push(name)
    }
  }
  return names
}

/** A plain copy of a record: its own and inherited accessor values, arrays and dates copied, the rest by reference. */
function copyValue(value: unknown, seen: WeakMap<object, unknown>, depth: number): unknown {
  if (value === null || typeof value !== 'object') return value
  if (depth > MAX_RECORD_DEPTH) throw new Error('the record nests deeper than the library follows')
  const known = seen.get(value)
  if (known !== undefined) return known
  if (value instanceof Date) return new Date(value.getTime())
  if (Array.isArray(value)) {
    const copy: unknown[] = []
    seen.set(value, copy)
    for (let index = 0; index < value.length; index += 1)
      copy.push(copyValue(value[index], seen, depth + 1))
    return copy
  }
  const proto = Object.getPrototypeOf(value) as object | null
  if (
    proto !== Object.prototype &&
    proto !== null &&
    !(proto.constructor?.name ?? '').match(/^[A-Z]/)
  )
    return value
  const copy: Record<string, unknown> = {}
  seen.set(value, copy)
  const source = value as Record<string, unknown>
  for (const key of new Set([...Object.keys(value), ...inheritedAccessors(value)])) {
    copy[key] = copyValue(source[key], seen, depth + 1)
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

/**
 * Wraps a repository of the host so that every record it returns is copied once.
 *
 * @param host - The host's repository.
 * @returns A repository with the same methods, answering with plain copies.
 */
export function guardRepository<T extends object>(host: T): T {
  return new Proxy(host, {
    get(target, key): unknown {
      const member: unknown = Reflect.get(target, key, target)
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
 * The guarded view of each repository the host provides, under the internal tokens the library's services inject.
 *
 * The host's own providers are left exactly as they are, so the token the module exports still resolves to the
 * host's instance.
 *
 * @param providers - The host's `extraProviders`.
 * @returns One provider per repository the host supplied.
 */
export function guardedProviders(providers: Provider[]): Provider[] {
  return [...GUARDED_BY_HOST]
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
}
