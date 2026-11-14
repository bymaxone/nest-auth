/**
 * @fileoverview Tests for the Redis outage classifier and the mapping that answers it with a 503.
 *
 * The error shapes below are not invented: each message and name was captured from a real ioredis
 * client against a paused container, a stopped one, and the two other client configurations a host
 * may use, and from a real Redis 8 server for the reply errors.
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import type { Redis } from 'ioredis'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import {
  isServiceUnavailable,
  mappingOutages,
  NETWORK_CODES,
  redisOutageKindOf,
  rethrowAsOutage,
  UNAVAILABLE_REPLIES
} from './redis-outage'

/** An error with the given name and message, as ioredis and its reply parser build them. */
function named(name: string, message: string, extra: object = {}): Error {
  return Object.assign(new Error(message), { name }, extra)
}

const MAX_RETRIES = named(
  'MaxRetriesPerRequestError',
  'Reached the max retries per request limit (which is 1). Refer to "maxRetriesPerRequest" option for details.'
)

const NETWORK_CODES_UNDER_TEST = [
  'ECONNREFUSED',
  'ECONNRESET',
  'ETIMEDOUT',
  'EPIPE',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EHOSTUNREACH',
  'ENETUNREACH'
] as const

interface Case {
  readonly label: string
  readonly error: unknown
  readonly kind: string | undefined
}

const OUTAGES: readonly Case[] = [
  {
    label: 'a paused or partitioned server',
    error: new Error('Command timed out'),
    kind: 'timeout'
  },
  { label: 'a closed connection', error: new Error('Connection is closed.'), kind: 'closed' },
  {
    label: 'a client with no offline queue',
    error: new Error("Stream isn't writeable and enableOfflineQueue options is false"),
    kind: 'closed'
  },
  { label: 'a bounded retry count', error: MAX_RETRIES, kind: 'unreachable' },
  ...NETWORK_CODES_UNDER_TEST.map((code) => ({
    label: `a ${code} network error`,
    error: named('Error', `connect ${code}`, { code }),
    kind: 'unreachable'
  })),
  ...['READONLY', 'LOADING', 'MASTERDOWN', 'CLUSTERDOWN', 'TRYAGAIN'].map((word) => ({
    label: `a ${word} reply`,
    error: named('ReplyError', `${word} the server cannot serve this now`),
    kind: 'unavailable'
  }))
]

const NOT_OUTAGES: readonly Case[] = [
  {
    label: 'a script that is not loaded',
    error: named('ReplyError', 'NOSCRIPT No matching script. Please use EVAL.'),
    kind: undefined
  },
  {
    label: 'a key of the wrong type',
    error: named('ReplyError', 'WRONGTYPE Operation against a key holding the wrong kind of value'),
    kind: undefined
  },
  {
    label: 'a script that fails',
    error: named('ReplyError', 'ERR Unknown Redis command called from script'),
    kind: undefined
  },
  { label: 'a reply error with no text', error: named('ReplyError', ''), kind: undefined },
  {
    label: 'a reply error whose later words are ours',
    error: named('ReplyError', 'ERR READONLY'),
    kind: undefined
  },
  { label: 'an error nobody classifies', error: new Error('boom'), kind: undefined },
  {
    label: 'a network code outside the list',
    error: named('Error', 'x', { code: 'EACCES' }),
    kind: undefined
  },
  {
    label: 'a code that is not a string',
    error: named('Error', 'x', { code: 111 }),
    kind: undefined
  },
  {
    label: 'a message that only contains one of ours',
    error: new Error('the Command timed out again'),
    kind: undefined
  },
  { label: 'a string', error: 'Command timed out', kind: undefined },
  { label: 'a plain object', error: { message: 'Command timed out' }, kind: undefined },
  { label: 'null', error: null, kind: undefined },
  { label: 'undefined', error: undefined, kind: undefined }
]

describe('redisOutageKindOf', () => {
  // Scenario: each way a real client reports a store that does not answer. Expected: the kind that
  // says why, so the conditions a host can be in stay distinguishable in one place.
  it.each(OUTAGES)('reads $label as $kind', ({ error, kind }) => {
    expect(redisOutageKindOf(error)).toBe(kind)
  })

  // Scenario: errors that are mistakes, not outages. Expected: not classified, so they stay the
  // internal failure they are and are never answered as "try again".
  it.each(NOT_OUTAGES)('does not read $label as an outage', ({ error }) => {
    expect(redisOutageKindOf(error)).toBeUndefined()
  })
})

describe('rethrowAsOutage', () => {
  // Scenario: an outage error. Expected: the typed 503 with the library's body, the original error
  // on `cause`, and nothing of the store's text in the body.
  it('throws the typed 503 with the original error as its cause', () => {
    const original = new Error('Command timed out')
    let thrown: unknown
    try {
      rethrowAsOutage(original)
    } catch (error) {
      thrown = error
    }

    expect(thrown).toBeInstanceOf(AuthException)
    const exception = thrown as AuthException
    expect(exception.getStatus()).toBe(503)
    expect(exception.getResponse()).toEqual({
      error: {
        code: 'auth.service_unavailable',
        message: 'Service temporarily unavailable',
        details: null
      }
    })
    expect(exception.cause).toBe(original)
    expect(JSON.stringify(exception.getResponse())).not.toContain('timed out')
  })

  // Scenario: an error that is not an outage. Expected: the very same object, untouched.
  it('rethrows any other error as it is', () => {
    const other = named(
      'ReplyError',
      'WRONGTYPE Operation against a key holding the wrong kind of value'
    )

    expect(() => rethrowAsOutage(other)).toThrow(other)
  })
})

describe('isServiceUnavailable', () => {
  it('recognises the typed 503 and nothing else', () => {
    expect(isServiceUnavailable(new AuthException(AUTH_ERROR_CODES.SERVICE_UNAVAILABLE))).toBe(true)
    expect(isServiceUnavailable(new AuthException(AUTH_ERROR_CODES.INTERNAL))).toBe(false)
    expect(isServiceUnavailable(new Error('Command timed out'))).toBe(false)
    expect(isServiceUnavailable(undefined)).toBe(false)
  })
})

describe('mappingOutages', () => {
  /** A client of arbitrary methods, as the proxy sees one. */
  function client(): Record<string, unknown> {
    return {
      status: 'ready',
      get: jest.fn(),
      anyCommandAddedLater: jest.fn(),
      synchronous: jest.fn()
    }
  }
  /** The proxy over a fake client. */
  function proxy(target: object): Redis {
    return mappingOutages(target as Redis)
  }
  /** The proxy read as the plain method table it behaves as. */
  function view(target: object): Record<string, (...args: unknown[]) => unknown> {
    const proxied: unknown = proxy(target)
    return proxied as Record<string, (...args: unknown[]) => unknown>
  }

  // Scenario: any method of the client rejects with an outage, a name nobody listed included.
  // Expected: the typed 503 with the cause, because the proxy wraps every method rather than a
  // list of commands.
  it.each(['get', 'anyCommandAddedLater'])('maps an outage raised by %s', async (method) => {
    const target = client()
    const original = new Error('Connection is closed.')
    ;(target[method] as jest.Mock).mockRejectedValue(original)

    const call: unknown = view(target)[method]?.('k')
    const rejection = (await Promise.resolve(call).catch(
      (error: unknown) => error
    )) as AuthException

    expect(rejection).toBeInstanceOf(AuthException)
    expect(rejection.cause).toBe(original)
  })

  // Scenario: a rejection that is not an outage. Expected: the same error object.
  it('passes any other rejection through untouched', async () => {
    const target = client()
    const other = named('ReplyError', 'NOSCRIPT No matching script. Please use EVAL.')
    ;(target['get'] as jest.Mock).mockRejectedValue(other)

    await expect(view(target)['get']?.('k')).rejects.toBe(other)
  })

  // Scenario: a command that succeeds. Expected: its value, with the arguments it was given and
  // the client as `this`.
  it('resolves a successful call with its value and calls it on the client', async () => {
    const target = client()
    ;(target['get'] as jest.Mock).mockImplementation(function (this: unknown, key: string) {
      return Promise.resolve(this === target ? `value:${key}` : 'wrong this')
    })

    await expect(view(target)['get']?.('k')).resolves.toBe('value:k')
  })

  // Scenario: a method that returns no promise, and a property that is not a method. Expected:
  // both pass through as they are.
  it('leaves a synchronous return value and a plain property as they are', () => {
    const target = client()
    ;(target['synchronous'] as jest.Mock).mockReturnValue('now')

    expect(view(target)['synchronous']?.()).toBe('now')
    expect(Reflect.get(proxy(target), 'status')).toBe('ready')
  })

  // Scenario: methods that return null, or an object that is not waited on (a pipeline-like
  // handle). Expected: returned as they are, never read for a `then`.
  it('passes through a null and a plain object return', () => {
    const target = client()
    const handle = { exec: jest.fn() }
    ;(target['synchronous'] as jest.Mock).mockReturnValueOnce(null).mockReturnValueOnce(handle)

    expect(view(target)['synchronous']?.()).toBeNull()
    expect(view(target)['synchronous']?.()).toBe(handle)
  })
})

/** The outage list both libraries pin, from the shared wire contract. */
const contract = JSON.parse(
  readFileSync(join(__dirname, '../../../conformance/wire-contract.json'), 'utf8')
) as {
  serviceUnavailable: {
    outage: {
      networkErrorCodes: string[]
      replyPrefixes: string[]
      notAnOutageReplyPrefixes: string[]
    }
  }
}

describe('redisOutageKindOf against the shared contract', () => {
  const { outage } = contract.serviceUnavailable

  // Scenario: each reply the contract lists as "cannot serve". Expected: an outage. The list is
  // the contract's, so a prefix added there that this classifier does not know fails here.
  it.each(outage.replyPrefixes)('reads a %s reply as an outage', (prefix) => {
    expect(
      redisOutageKindOf(named('ReplyError', `${prefix} the server cannot serve this now`))
    ).toBe('unavailable')
  })

  // Scenario: each reply the contract names as a mistake. Expected: not an outage.
  it.each(outage.notAnOutageReplyPrefixes)('does not read a %s reply as an outage', (prefix) => {
    expect(
      redisOutageKindOf(named('ReplyError', `${prefix} a mistake, not a condition`))
    ).toBeUndefined()
  })

  // Scenario: each network error code the contract lists. Expected: unreachable.
  it.each(outage.networkErrorCodes)('reads the network code %s as unreachable', (code) => {
    expect(redisOutageKindOf(named('Error', `connect ${code}`, { code }))).toBe('unreachable')
  })

  // Scenario: the classifier's own sets against the contract's lists, in both directions. Expected:
  // equal, so a prefix or a code added on either side alone fails here, not in production.
  it('holds exactly the contract lists', () => {
    expect([...UNAVAILABLE_REPLIES].sort()).toEqual([...outage.replyPrefixes].sort())
    expect([...NETWORK_CODES].sort()).toEqual([...outage.networkErrorCodes].sort())
  })
})
