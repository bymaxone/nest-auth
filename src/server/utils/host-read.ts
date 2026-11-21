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
  CREDENTIAL_FIELDS,
  MEMBERSHIP_REPOSITORY_CONTRACT,
  PLATFORM_USER_REPOSITORY_CONTRACT,
  USER_REPOSITORY_CONTRACT,
  WORKSPACE_REPOSITORY_CONTRACT,
  type ErasedContract,
  type ErasedRepositoryContract
} from './repository-contracts'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/** The most elements of an array and the most keys of an object a copy follows; a host that answers more is refused. */
const MAX_BREADTH = 100_000

/** What a copy remembers so that a value reached twice under a contract is copied once, by value and contract together. */
type Seen = WeakMap<object, Map<ErasedContract, unknown>>

/** What was already copied from a value under a contract. */
function copiedUnder(seen: Seen, value: object, contract: ErasedContract): unknown {
  return seen.get(value)?.get(contract)
}

/** Remembers a copy of a value under a contract. */
function rememberUnder(seen: Seen, value: object, contract: ErasedContract, copy: unknown): void {
  const copies = seen.get(value) ?? new Map<ErasedContract, unknown>()
  copies.set(contract, copy)
  seen.set(value, copies)
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

/**
 * Sets a field on a copy by defining it, never by assigning it: a key named `__proto__` (what `JSON.parse` of user
 * input produces) would swap the prototype, and a name that is a setter on `Object.prototype` would be silently
 * dropped. The caller says whether the field shows in a spread of the copy.
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

/** Whether an object is plain: made by an object literal or `Object.create(null)`, in this realm or in another. */
function isPlainObject(value: object): boolean {
  const prototype: unknown = Object.getPrototypeOf(value)
  return prototype === null || Object.getPrototypeOf(prototype as object) === null
}

/** A contract that reads a record or a list, as opposed to a plain answer, and one that reads a record. */
type Structured = Exclude<ErasedContract, string>
type RecordContract = Extract<ErasedContract, { fields: unknown }>

/** The reasons a copy refuses an answer. None repeats anything the host answered. */
const WRONG_KIND = 'the answer holds a value that is not the kind its method promises'
const ABSENT = 'the answer lacks a field its method promises'
const NOT_A_TIME = 'the answer holds a date that is not a time'

/** The value itself when it is of the kind, and a refusal when it is not. */
function accept(ok: boolean, value: unknown): unknown {
  if (!ok) throw new Error(WRONG_KIND)
  return value
}

/**
 * Whether a value is an instance of a class of the host (an id type of a database driver): an object that is not plain,
 * not an array and not a wrapper of a primitive, since `new Boolean(false)` is truthy and is no boolean.
 */
function isHostInstance(value: unknown): boolean {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    !types.isBoxedPrimitive(value) &&
    !isPlainObject(value)
  )
}

/** A copy of a date, read through the object that answers as one; its time has to be a number that is a time. */
function copyDate(value: unknown): Date {
  if (typeof value !== 'object' || value === null || !isDateLike(value)) throw new Error(WRONG_KIND)
  const time: unknown = value.getTime()
  const copy = new Date(typeof time === 'number' ? time : Number.NaN)
  if (Number.isNaN(copy.getTime())) throw new Error(NOT_A_TIME)
  return copy
}

/** A copy of a list of strings. */
function copyStrings(value: unknown): string[] {
  if (!Array.isArray(value)) throw new Error(WRONG_KIND)
  refuseBreadth(value.length)
  const copy: string[] = []
  for (let index = 0; index < value.length; index += 1)
    copy.push(accept(typeof value[index] === 'string', value[index]) as string)
  return copy
}

/**
 * An id, a name or any other string a field only informs with: a string, a finite number, or an instance of a class of
 * the host (an id type of a driver) kept as the host's own object. A function, a symbol, a bigint and the rest are
 * refused.
 */
function readInforming(value: unknown): unknown {
  return accept(
    typeof value === 'string' ||
      (typeof value === 'number' && Number.isFinite(value)) ||
      isHostInstance(value),
    value
  )
}

/**
 * A date a field only informs with: a real date is copied, and any other instance (a date library's date, an Invalid
 * Date) is kept as the host's own object; anything else is refused.
 */
function readInformingDate(value: unknown): unknown {
  if (!isHostInstance(value)) throw new Error(WRONG_KIND)
  return isDateLike(value as object) && Number.isFinite((value as Date).getTime())
    ? copyDate(value)
    : value
}

/**
 * How a value is read as each kind a contract can name. A strict kind is exact: a wrapper object is not a boolean, a
 * string is not a number, a date has a real time, and only an `id` may be an instance of a class of the host. A kind
 * marked `~` only informs: it is lenient about what it takes (see {@link readInforming}).
 */
const READERS = {
  boolean: (value: unknown): unknown => accept(typeof value === 'boolean', value),
  string: (value: unknown): unknown => accept(typeof value === 'string', value),
  number: (value: unknown): unknown =>
    accept(typeof value === 'number' && Number.isFinite(value), value),
  id: (value: unknown): unknown =>
    accept(typeof value === 'string' || isHostInstance(value), value),
  date: copyDate,
  strings: copyStrings,
  '~id': readInforming,
  '~string': readInforming,
  '~date': readInformingDate
} as const

/** The kinds that are read by a reader of their own. */
type ReaderName = keyof typeof READERS

/**
 * The kind a field is read as, whether `null` is promised and whether it may be absent, from its spec. A lenient kind
 * (`~`) accepts both: a field that only informs is never worth refusing an answer for.
 */
function parseSpec(spec: string): { base: string; nullable: boolean; optional: boolean } {
  const lenient = spec.startsWith('~')
  const optional = lenient || spec.endsWith('?')
  const rest = spec.endsWith('?') ? spec.slice(0, -1) : spec
  const nullable = lenient || rest.endsWith('|null')
  return {
    base: rest.endsWith('|null') ? rest.slice(0, -'|null'.length) : rest,
    nullable,
    optional
  }
}

/** `null`, when the contract promises it. */
function readNull(nullable: boolean): null {
  if (!nullable) throw new Error(WRONG_KIND)
  return null
}

/** What a method answers that is no record: its kind, or nothing for a method that answers nothing. */
function readScalar(value: unknown, spec: string): unknown {
  const { base, nullable } = parseSpec(spec)
  if (base === 'void') return undefined
  return value === null ? readNull(nullable) : READERS[base as ReaderName](value)
}

/**
 * Copies the fields of a record that its contract names, each as the kind the contract gives it, and hands the rest
 * of the record on without reading it. A field the contract names is read by name once, so it is found wherever the
 * host keeps it (an own field, a prototype getter, a lazy entity that lists nothing), and it shows in a spread of the
 * copy, except a credential, which shows only if the host's own record showed it. A field the interface requires is
 * refused when it is absent: absent would read as the default of its type, and `mfaEnabled` as absent is off. A field
 * the interface allows to be absent may also be `null`, which is how a column that holds nothing arrives from an ORM. Any
 * other own field that holds data is handed on by reference through its descriptor, which evaluates nothing; one that
 * is an accessor is left out, because reading it is what the contract forbids.
 */
function copyRecord(value: object, contract: RecordContract, seen: Seen): unknown {
  const copy: Record<string, unknown> = {}
  rememberUnder(seen, value, contract, copy)
  ENTITIES.set(copy, value)
  const source = value as Record<string, unknown>
  const keys = Object.keys(value)
  refuseBreadth(keys.length)
  for (const key of keys) {
    if (Object.hasOwn(contract.fields, key)) continue
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (descriptor !== undefined && 'value' in descriptor) define(copy, key, descriptor.value, true)
  }
  const own = new Set(keys)
  for (const [field, spec] of Object.entries(contract.fields)) {
    const { base, nullable, optional } = parseSpec(spec)
    const read = source[field]
    if (read === undefined) {
      if (optional) continue
      throw new Error(ABSENT)
    }
    const copied =
      read === null
        ? readNull(nullable || optional)
        : base === 'nested'
          ? applyContract(read, contract.nested[field] as Structured, seen)
          : READERS[base as ReaderName](read)
    define(copy, field, copied, own.has(field) || !CREDENTIAL_FIELDS.has(field))
  }
  return copy
}

/** What the guarded view answers for an object, given the record or list its method promises. */
function applyContract(value: unknown, contract: Structured, seen: Seen): unknown {
  if (typeof value !== 'object' || value === null) throw new Error(WRONG_KIND)
  const known = copiedUnder(seen, value, contract)
  if (known !== undefined) return known
  if ('list' in contract) {
    if (!Array.isArray(value)) throw new Error('the answer is not the list its method promises')
    refuseBreadth(value.length)
    const copy: unknown[] = []
    rememberUnder(seen, value, contract, copy)
    for (let index = 0; index < value.length; index += 1)
      copy.push(applyContract(value[index], contract.list as Structured, seen))
    return copy
  }
  if (Array.isArray(value)) throw new Error('the answer is not the record its method promises')
  return copyRecord(value, contract, seen)
}

/**
 * Copies what a repository method returned, so a failed read of it ends here.
 *
 * @param record - What the repository returned.
 * @param contract - What the method promises to return, and so what is read from it.
 * @returns A copy of a record or a list, the plain answer when the method answers one, or `null` or `undefined` for a
 *   record that was not found.
 * @throws {@link AuthException} `INTERNAL` whose `cause` is the host's error.
 */
export function copyHostRecord(record: unknown, contract: ErasedContract): unknown {
  try {
    if (typeof contract === 'string') return readScalar(record, contract)
    return record === null || record === undefined
      ? record
      : applyContract(record, contract, new WeakMap())
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
