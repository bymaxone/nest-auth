/**
 * @fileoverview Tests for {@link NoStoreInterceptor}.
 *
 * The property under test: every response of every controller this library registers
 * carries `Cache-Control: no-store` — a login response cached by a CDN or corporate
 * proxy is one user's tokens served to the next caller, and RFC 6749 §5.1 makes the
 * header mandatory on any response carrying a token.
 */

import { INTERCEPTORS_METADATA } from '@nestjs/common/constants'

import { NoStoreInterceptor } from './no-store.interceptor'
import { AuthController } from '../controllers/auth.controller'
import { InvitationController } from '../controllers/invitation.controller'
import { MfaController } from '../controllers/mfa.controller'
import { PasswordResetController } from '../controllers/password-reset.controller'
import { PlatformAuthController } from '../controllers/platform-auth.controller'
import { PlatformMfaController } from '../controllers/platform-mfa.controller'
import { SessionController } from '../controllers/session.controller'
import { OAuthController } from '../oauth/oauth.controller'

import type { CallHandler, ExecutionContext } from '@nestjs/common'

/** A minimal ExecutionContext exposing a header-recording response. */
function makeContext(): { ctx: ExecutionContext; headers: Record<string, string> } {
  const headers: Record<string, string> = {}
  const response = {
    setHeader: (name: string, value: string) => {
      headers[name] = value
    }
  }
  const ctx = {
    switchToHttp: () => ({ getResponse: () => response })
  } as unknown as ExecutionContext
  return { ctx, headers }
}

describe('NoStoreInterceptor', () => {
  const interceptor = new NoStoreInterceptor()

  // Scenario: an ordinary handler. Expected: both cache headers are set and the handler's
  // own stream is returned untouched — the interceptor never wraps or subscribes, so it can
  // be tested without rxjs (which this zero-dependency package does not declare).
  it('should stamp no-store and return the handler stream untouched', () => {
    const { ctx, headers } = makeContext()
    const stream = Symbol('handler-stream')
    const next = { handle: () => stream } as unknown as CallHandler

    expect(interceptor.intercept(ctx, next)).toBe(stream)
    expect(headers['Cache-Control']).toBe('no-store')
    expect(headers['Pragma']).toBe('no-cache')
  })

  // Scenario: the handler throws. Expected: the headers are ALREADY on the response. Why:
  // the header is set before the handler runs precisely so an AuthException mid-handler
  // still produces an uncacheable error response — a cached 401 wedges a client just as a
  // cached login leaks one.
  it('should stamp the headers before the handler runs, so error responses carry them', () => {
    const { ctx, headers } = makeContext()
    const next = {
      handle: () => {
        throw new Error('boom')
      }
    } as unknown as CallHandler

    expect(() => interceptor.intercept(ctx, next)).toThrow('boom')
    expect(headers['Cache-Control']).toBe('no-store')
    expect(headers['Pragma']).toBe('no-cache')
  })

  // Scenario: the full roster of controllers this library registers. Expected: every one
  // carries the interceptor at class level. Why: applying the header per-route invites the
  // one forgotten endpoint to be the leak — this test makes a NEW controller without the
  // interceptor a failing build, not a silent regression.
  it('should be applied to every controller the library registers', () => {
    const controllers = [
      AuthController,
      InvitationController,
      MfaController,
      PasswordResetController,
      PlatformAuthController,
      PlatformMfaController,
      SessionController,
      OAuthController
    ]

    for (const controller of controllers) {
      const interceptors = Reflect.getMetadata(INTERCEPTORS_METADATA, controller) as unknown[]
      expect(interceptors).toBeDefined()
      expect(interceptors).toContain(NoStoreInterceptor)
    }
  })
})
