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
import {
  API_KEY_REPOSITORY_CONTRACT,
  MEMBERSHIP_REPOSITORY_CONTRACT,
  PLATFORM_USER_REPOSITORY_CONTRACT,
  USER_REPOSITORY_CONTRACT,
  WORKSPACE_REPOSITORY_CONTRACT,
  type ErasedContract,
  type ErasedRepositoryContract
} from './repository-contracts'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/** The most levels of nesting a record copy follows; a record deeper than this is not a record. */
const MAX_RECORD_DEPTH = 16

/** The most elements of an array and the most keys of an object a copy follows; a host that answers more is refused. */
const MAX_BREADTH = 100_000

/**
 * What a copy remembers so that a value reached twice is copied once: data by value, and what was copied under a
 * contract by value and contract together, because the same object copied under another contract is another copy.
 */
interface Seen {
  readonly data: WeakMap<object, unknown>
  readonly contracts: WeakMap<object, Map<ErasedContract, unknown>>
}

/** What was already copied from a value under a contract. */
function copiedUnder(seen: Seen, value: object, contract: ErasedContract): unknown {
  return seen.contracts.get(value)?.get(contract)
}

/** Remembers a copy of a value under a contract. */
function rememberUnder(seen: Seen, value: object, contract: ErasedContract, copy: unknown): void {
  const copies = seen.contracts.get(value) ?? new Map<ErasedContract, unknown>()
  copies.set(contract, copy)
  seen.contracts.set(value, copies)
}

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

/**
 * Sets a field on a copy by defining it, never by assigning it: a key named `__proto__` (what `JSON.parse` of user
 * input produces) would swap the prototype, and a name that is a setter on `Object.prototype` would be silently
 * dropped. A field is enumerable only when it was enumerable on the record, so a spread of the copy shows what a
 * spread of the record showed and a hidden field is still readable by name.
 */
function define(copy: object, key: string, value: unknown, enumerable: boolean): void {
  Object.defineProperty(copy, key, { value, enumerable, writable: true, configurable: true })
}

/** The object the host's repository returned behind each copy of it. Filled by the copy itself, which is the only read. */
const ENTITIES = new WeakMap<object, object>()

/** Refuses an array or an object that holds more than a copy follows. */
function refuseBreadth(size: number): void {
  if (size > MAX_BREADTH) throw new Error('the answer holds more than the library follows')
}

/**
 * Whether a value is a date: one by its internal slot, which holds across realms, or a Proxy of the host whose
 * prototype chain holds `Date.prototype`. A Proxy has no slot, so `Date.prototype.getTime.call(proxy)` throws even for
 * a Proxy of a date and cannot tell the two apart; the chain, read through the Proxy, can, and an object that only
 * has methods named like a date's is not taken for one.
 */
function isDateLike(value: object): value is Date {
  return types.isDate(value) || (types.isProxy(value) && value instanceof Date)
}

/**
 * A plain copy of a value the contract names no fields of: dates and arrays copied, objects copied field by field,
 * the other kinds of object by reference.
 */
function copyData(value: unknown, seen: Seen, depth: number): unknown {
  if (value === null || typeof value !== 'object') return value
  if (depth > MAX_RECORD_DEPTH) throw new Error('the record nests deeper than the library follows')
  const known = seen.data.get(value)
  if (known !== undefined) return known
  if (isDateLike(value)) {
    const copy = new Date(Number(value.getTime()))
    // A date that is not a time compares false with every instant, so a deadline read from it is never due.
    if (Number.isNaN(copy.getTime())) throw new Error('the answer holds a date that is not a time')
    return copy
  }
  if (Array.isArray(value)) {
    refuseBreadth(value.length)
    const copy: unknown[] = []
    seen.data.set(value, copy)
    for (let index = 0; index < value.length; index += 1)
      copy.push(copyData(value[index], seen, depth + 1))
    return copy
  }
  if (isOpaque(value)) return value
  const copy: Record<string, unknown> = {}
  seen.data.set(value, copy)
  const source = value as Record<string, unknown>
  const keys = Object.keys(value)
  refuseBreadth(keys.length)
  for (const key of keys) define(copy, key, copyData(source[key], seen, depth + 1), true)
  return copy
}

/**
 * Copies the fields of a record that its contract names, and hands the rest of the record on without reading it.
 * A field the contract names is read by name once, so it is found wherever the host keeps it (an own field, a
 * prototype getter, a lazy entity that lists nothing), and a field that is not own and enumerable stays hidden on the
 * copy. Any other own field that holds data is handed on by reference through its descriptor, which evaluates
 * nothing; one that is an accessor is left out, because reading it is what the contract forbids.
 */
function copyRecord(
  value: object,
  contract: Extract<ErasedContract, { fields: unknown }>,
  seen: Seen,
  depth: number
): unknown {
  const copy: Record<string, unknown> = {}
  rememberUnder(seen, value, contract, copy)
  ENTITIES.set(copy, value)
  const source = value as Record<string, unknown>
  const done = new Set<string>()
  const take = (field: string, enumerable: boolean): void => {
    done.add(field)
    const read = source[field]
    if (read === undefined || typeof read === 'function') return
    const nested = Object.hasOwn(contract.nested, field) ? contract.nested[field] : undefined
    const copied =
      nested === undefined
        ? copyData(read, seen, depth + 1)
        : applyContract(read, nested, seen, depth + 1)
    define(copy, field, copied, enumerable)
  }
  const keys = Object.keys(value)
  refuseBreadth(keys.length)
  for (const key of keys) {
    if (Object.hasOwn(contract.fields, key)) {
      take(key, true)
      continue
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (descriptor !== undefined && 'value' in descriptor) define(copy, key, descriptor.value, true)
  }
  for (const field of Object.keys(contract.fields)) if (!done.has(field)) take(field, false)
  return copy
}

/** What the guarded view answers for a value, given what its method promises. */
function applyContract(
  value: unknown,
  contract: ErasedContract,
  seen: Seen,
  depth: number
): unknown {
  if (contract === 'value') return copyData(value, seen, depth)
  if (value === null || typeof value !== 'object') return value
  const known = copiedUnder(seen, value, contract)
  if (known !== undefined) return known
  if ('list' in contract) {
    if (!Array.isArray(value)) throw new Error('the answer is not the list its method promises')
    refuseBreadth(value.length)
    const copy: unknown[] = []
    rememberUnder(seen, value, contract, copy)
    for (let index = 0; index < value.length; index += 1)
      copy.push(applyContract(value[index], contract.list, seen, depth + 1))
    return copy
  }
  if (Array.isArray(value)) throw new Error('the answer is not the record its method promises')
  return copyRecord(value, contract, seen, depth)
}

/**
 * Copies what a repository method returned, so a failed read of it ends here.
 *
 * @param record - What the repository returned.
 * @param contract - What the method promises to return, and so what is read from it.
 * @returns A plain copy, or `record` itself when it is not an object.
 * @throws {@link AuthException} `INTERNAL` whose `cause` is the host's error.
 */
export function copyHostRecord(record: unknown, contract: ErasedContract): unknown {
  try {
    return applyContract(record, contract, { data: new WeakMap(), contracts: new WeakMap() }, 0)
  } catch (error: unknown) {
    throw new AuthException(AUTH_ERROR_CODES.INTERNAL, undefined, { cause: error })
  }
}

/** Whether a failure is a typed error the host chose to throw. The test is itself a read of the host's error. */
function isTypedError(error: unknown): error is HttpException {
  try {
    return error instanceof HttpException
  } catch {
    return false
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
 * The entity the host's repository returned for a record the guarded view copied, or the value itself when it is
 * not such a record. Code of the host (a callback the library invokes) is handed its own object, so its prototype
 * getters, methods and private fields work, while the library keeps reading the copy.
 *
 * @param record - A record read through a guarded repository, or any other value.
 * @returns The host's own entity, or `record` unchanged.
 */
export function hostEntityOf<T>(record: T): T {
  return typeof record === 'object' && record !== null
    ? ((ENTITIES.get(record) as T | undefined) ?? record)
    : record
}

/**
 * Wraps a repository of the host so that every record it returns is copied once, reading from each answer only the
 * fields its method promises.
 *
 * @param host - The host's repository.
 * @param contract - What each method of the repository promises to return.
 * @returns A repository with the same methods, answering with plain copies.
 */
export function guardRepository<T extends object>(host: T, contract: ErasedRepositoryContract): T {
  // The target is a separate object: a proxy over a frozen host would have to return each own member untouched.
  return new Proxy({} as T, {
    get(_target, key): unknown {
      // Nest calls a lifecycle hook on every provider instance, and this view is a second one over the repository.
      if (LIFECYCLE_HOOKS.has(key)) return undefined
      let member: unknown
      try {
        member = Reflect.get(host, key, host)
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
          answer = await (member as (...parameters: unknown[]) => unknown).apply(host, args)
        } catch (error: unknown) {
          // A typed error the host chose to throw (a unique-key conflict it maps to `AuthException`) goes out as it is.
          if (isTypedError(error)) throw error
          throw new AuthException(AUTH_ERROR_CODES.INTERNAL, undefined, { cause: error })
        }
        // A method the interface does not have is not one the library calls: its answer goes out as the host gave it.
        const promised =
          typeof key === 'string' && Object.hasOwn(contract, key) ? contract[key] : undefined
        return promised === undefined ? answer : copyHostRecord(answer, promised)
      }
    }
  })
}

/** The guarded token and the contract of each repository the host may provide, keyed by the host's token. */
const GUARDED_BY_HOST: ReadonlyMap<symbol, readonly [symbol, ErasedRepositoryContract]> = new Map([
  [BYMAX_AUTH_USER_REPOSITORY, [GUARDED_USER_REPOSITORY, USER_REPOSITORY_CONTRACT]],
  [
    BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
    [GUARDED_PLATFORM_USER_REPOSITORY, PLATFORM_USER_REPOSITORY_CONTRACT]
  ],
  [BYMAX_AUTH_API_KEY_REPOSITORY, [GUARDED_API_KEY_REPOSITORY, API_KEY_REPOSITORY_CONTRACT]],
  [BYMAX_AUTH_WORKSPACE_REPOSITORY, [GUARDED_WORKSPACE_REPOSITORY, WORKSPACE_REPOSITORY_CONTRACT]],
  [
    BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
    [GUARDED_MEMBERSHIP_REPOSITORY, MEMBERSHIP_REPOSITORY_CONTRACT]
  ]
])

/**
 * The provider of the guarded view of one repository: the host's repository, read through the guard, under the
 * internal token the library's services inject.
 *
 * @param host - The token the host provides its repository under.
 * @param guarded - The internal token of the view.
 * @param contract - What each method of the repository promises to return.
 * @returns A provider resolving `guarded` to the guarded view of what `host` resolves to.
 */
export function guardedViewProvider(
  host: symbol,
  guarded: symbol,
  contract: ErasedRepositoryContract
): Provider {
  return {
    provide: guarded,
    useFactory: (repository: object): object => guardRepository(repository, contract),
    inject: [host]
  }
}

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
    .map(([host, [guarded, contract]]) => guardedViewProvider(host, guarded, contract))
  return [...providers, ...views]
}
