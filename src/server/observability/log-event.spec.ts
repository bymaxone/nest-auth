/**
 * @fileoverview A log event reaches the host's logger as one object, at the level the catalog gives it, and a
 * host logger that throws synchronously does not change what the flow that logged does.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'
import type { LoggerService } from '@nestjs/common'

import { logEvent } from './log-event'
import { AUTH_LOG_EVENTS } from './log-events'
import type { AuthLogEvent } from './log-events'

/** A host logger that records what it receives and, when asked, throws from the method of a level. */
function hostLogger(throwingLevel?: 'log' | 'warn' | 'error'): LoggerService & {
  received: Array<[string, unknown[]]>
} {
  const received: Array<[string, unknown[]]> = []
  const at =
    (level: 'log' | 'warn' | 'error') =>
    (...args: unknown[]): void => {
      received.push([level, args])
      if (level === throwingLevel) throw new Error('the host logger broke')
    }
  return { received, log: at('log'), warn: at('warn'), error: at('error') }
}

describe('logEvent', () => {
  afterEach(() => {
    Logger.overrideLogger(['log', 'warn', 'error', 'debug', 'verbose', 'fatal'])
  })

  // Scenario: every event of the catalog, written through a real Nest Logger over a host logger. Expected: the
  // host receives one object at the catalog's level, with the code, the catalog's message and the fields.
  it.each(Object.keys(AUTH_LOG_EVENTS) as AuthLogEvent[])(
    'writes %s as one object at its catalog level through a Nest Logger',
    (event) => {
      const host = hostLogger()
      Logger.overrideLogger(host)
      const fields = { plane: 'dashboard', flow: 'challenge' }

      logEvent(new Logger('Unit'), event, fields)

      expect(host.received).toHaveLength(1)
      const [level, args] = host.received[0] as [string, unknown[]]
      expect(level).toBe(AUTH_LOG_EVENTS[event].level)
      expect(args[0]).toStrictEqual({ ...fields, event, message: AUTH_LOG_EVENTS[event].message })
    }
  )

  // Scenario: a field named like the code or the message. Expected: the event keeps the catalog's code and
  // text. Why: the message is library text, and no caller may put a value in it.
  it('does not let a field replace the code or the message', () => {
    const host = hostLogger()
    Logger.overrideLogger(host)

    logEvent(new Logger('Unit'), 'AUTH_LOGIN_LOCKED', { event: 'forged', message: 'forged' })

    expect(host.received[0]?.[1][0]).toStrictEqual({
      event: 'AUTH_LOGIN_LOCKED',
      message: AUTH_LOG_EVENTS.AUTH_LOGIN_LOCKED.message
    })
  })

  // Scenario: the host logger throws synchronously at each level, through a real Nest Logger. Expected: the call
  // returns, so the flow that logged goes on and answers as it would have. A Nest Logger does not return what
  // the host's `LoggerService` returns, so an asynchronous logger that rejects is the host's own unhandled
  // rejection and is not covered here.
  it.each([
    ['AUTH_LOGIN_LOCKED', 'warn'],
    ['AUTH_OTP_STORE_FAILED', 'error']
  ] as const)('goes on when the host logger throws at %s (%s)', (event, level) => {
    const host = hostLogger(level)
    Logger.overrideLogger(host)

    expect(() => logEvent(new Logger('Unit'), event, { detail: 'x' })).not.toThrow()

    expect(host.received).toHaveLength(1)
  })
})
