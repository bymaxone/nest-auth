/**
 * @fileoverview Counts and traces an authentication route from what it returns or what it throws.
 *
 * The route handlers stay thin: a decorator names the operation and the plane, and this interceptor reads the
 * outcome from the result or from the library error code, bumps the closed-set count, and runs the handler
 * inside the span. Nothing the caller sent and nothing a host supplied is read, so no label or attribute can
 * carry an identity.
 *
 * @layer Interceptor
 */

import {
  applyDecorators,
  Inject,
  Injectable,
  Optional,
  SetMetadata,
  UseInterceptors
} from '@nestjs/common'
import type { CallHandler, ExecutionContext, NestInterceptor } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { from } from 'rxjs'
import type { Observable } from 'rxjs'

import { AuthMetricsTally } from './auth-metrics-tally'
import type { LoginOutcome, MfaOutcome, RefreshOutcome } from './auth-metrics-tally'
import { AuthTracing } from './auth-tracing'
import type { AuthSpanName } from './auth-tracing'
import { observedRefusal } from './observed-outcome'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { AuthPlane } from '../services/auth-token-verifier.service'

/** The operations a route can be observed as. */
export type ObservedOperation = 'login' | 'refresh' | 'mfa_verify' | 'password_reset'

/** What the decorator records on the handler. */
interface ObserveMetadata {
  readonly operation: ObservedOperation
  readonly plane: AuthPlane
}

/** Reflect metadata key carrying the operation and the plane. */
export const OBSERVE_AUTH_METADATA = 'bymax-one:observe-auth'

const SPAN_NAMES: Readonly<Record<ObservedOperation, AuthSpanName>> = {
  login: 'auth.login',
  refresh: 'auth.refresh',
  mfa_verify: 'auth.mfa.verify',
  password_reset: 'auth.password_reset'
}

const BLOCKED_CODES: ReadonlySet<string> = new Set([
  AUTH_ERROR_CODES.ACCOUNT_INACTIVE,
  AUTH_ERROR_CODES.ACCOUNT_SUSPENDED,
  AUTH_ERROR_CODES.ACCOUNT_BANNED,
  AUTH_ERROR_CODES.PENDING_APPROVAL
])

/** The library error code of a failure, or `undefined` when it is not one of the library's. */
function codeOf(error: unknown): string | undefined {
  if (!(error instanceof AuthException)) return undefined
  const code: unknown = (error.getResponse() as { error?: { code?: unknown } }).error?.code
  return typeof code === 'string' ? code : undefined
}

/** What a login ended as, or `undefined` for an end that is not one of the counted outcomes. */
function loginOutcome(result: unknown, error: unknown): LoginOutcome | undefined {
  if (error === undefined) {
    return (result as { mfaRequired?: unknown } | null)?.mfaRequired === true
      ? 'mfa_required'
      : 'success'
  }
  const code = codeOf(error)
  if (code === AUTH_ERROR_CODES.INVALID_CREDENTIALS) return 'invalid_credentials'
  if (code === AUTH_ERROR_CODES.ACCOUNT_LOCKED) return 'locked'
  return code !== undefined && BLOCKED_CODES.has(code) ? 'blocked' : undefined
}

/** What a refresh ended as, or `undefined` for an end that is not one of the counted outcomes. */
function refreshOutcome(error: unknown, failed: boolean): RefreshOutcome | undefined {
  if (!failed) return 'rotated'
  const marked = observedRefusal(error)
  if (marked !== undefined) return marked
  return codeOf(error) === AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID ? 'invalid' : undefined
}

/** What an MFA verification ended as, or `undefined` for an end that is not one of the counted outcomes. */
function mfaOutcome(error: unknown, failed: boolean): MfaOutcome | undefined {
  if (!failed) return 'success'
  const code = codeOf(error)
  if (code === AUTH_ERROR_CODES.MFA_INVALID_CODE) return 'invalid'
  return code === AUTH_ERROR_CODES.ACCOUNT_LOCKED ? 'locked' : undefined
}

/**
 * Counts and traces the routes marked with {@link ObserveAuth}.
 *
 * Counting is best effort and never changes what the route answers: a result or an error passes through
 * untouched, and an outcome that is not one of the closed set is not counted.
 */
@Injectable()
export class AuthObservabilityInterceptor implements NestInterceptor {
  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Optional() @Inject(AuthMetricsTally) private readonly tally?: AuthMetricsTally,
    @Optional() @Inject(AuthTracing) private readonly tracing?: AuthTracing
  ) {}

  /** Runs the handler inside the span and counts how it ended. */
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const meta = this.reflector.get<ObserveMetadata | undefined>(
      OBSERVE_AUTH_METADATA,
      context.getHandler()
    )
    // A controller mounted in a module that does not carry the observability providers is not observed.
    if (meta === undefined || this.tally === undefined || this.tracing === undefined) {
      return next.handle()
    }
    const { operation, plane } = meta
    const run = async (): Promise<unknown> => {
      let result: unknown
      let failure: unknown
      let failed = false
      try {
        result = await new Promise((resolve, reject) => {
          next
            .handle()
            .subscribe({ next: resolve, error: reject, complete: () => resolve(undefined) })
        })
      } catch (error) {
        failed = true
        failure = error
      }
      this.count(operation, plane, result, failure, failed)
      if (failed) throw failure
      return result
    }
    return from(this.tracing.span(SPAN_NAMES[operation], { 'bymax.auth.plane': plane }, run))
  }

  /** Bumps the count for how the operation ended, when that is one of the counted outcomes. */
  private count(
    operation: ObservedOperation,
    plane: AuthPlane,
    result: unknown,
    error: unknown,
    failed: boolean
  ): void {
    if (operation === 'login') {
      const outcome = loginOutcome(result, failed ? error : undefined)
      if (outcome !== undefined) this.tally?.login(plane, outcome)
    } else if (operation === 'refresh') {
      const outcome = refreshOutcome(error, failed)
      if (outcome !== undefined) this.tally?.refresh(plane, outcome)
    } else if (operation === 'mfa_verify') {
      const outcome = mfaOutcome(error, failed)
      if (outcome !== undefined) this.tally?.mfa(plane, outcome)
    }
  }
}

/**
 * Observes a route: counts how it ends and runs it inside a span.
 *
 * @param operation - What the route does.
 * @param plane - The plane it runs on.
 * @returns The decorator.
 */
export function ObserveAuth(operation: ObservedOperation, plane: AuthPlane): MethodDecorator {
  return applyDecorators(
    SetMetadata(OBSERVE_AUTH_METADATA, { operation, plane } satisfies ObserveMetadata),
    UseInterceptors(AuthObservabilityInterceptor)
  )
}
