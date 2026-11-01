/**
 * @fileoverview Authenticates machine callers by service API key and enforces route scopes.
 *
 * @layer Guard
 */

import { Inject, Injectable, Logger, Optional } from '@nestjs/common'
import type { CanActivate, ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import type { Request } from 'express'

import { BYMAX_AUTH_HOOKS, BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { API_KEY_SCOPES_KEY } from '../decorators/api-key-scopes.decorator'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { ApiKeyPrincipal, AuthApiKey } from '../interfaces/api-key-repository.interface'
import type {
  ApiKeyAccessEvent,
  ApiKeyDenyReason,
  HookContext,
  IAuthHooks
} from '../interfaces/auth-hooks.interface'
import { ApiKeyVerifierService } from '../services/api-key-verifier.service'
import { resolveClientAddress } from '../utils/client-address'
import { describeChannelStatus } from '../utils/describe-error'
import { logSafe } from '../utils/log-safe'
import { sanitizeHeaders } from '../utils/sanitize-headers'

/** A request after this guard admitted it. */
type ApiKeyRequest = Request & { apiKey?: ApiKeyPrincipal }

/**
 * Admits a request only when it presents a valid service key holding every scope the route
 * declares.
 *
 * **Fails closed.** A route this guard is bound to with no non-empty scope declaration is
 * refused before any credential is read, so a forgotten `@ApiKeyScopes` can never become an
 * open route. That branch deliberately takes different steps from the credential paths: it
 * depends on route configuration, not on the key, so there is nothing for the key to leak.
 *
 * Every request ends in exactly one `onApiKeyRequest` event, refusals included. The presented
 * key and its secret appear in no log line, exception, event or `request.apiKey`.
 *
 * @example
 * ```typescript
 * @ServiceKey('read')            // binds this guard and lets the route past the user JWT guards
 * @Get('videos')
 * list(@CurrentApiKey() key: ApiKeyPrincipal) { ... }
 * ```
 */
@Injectable()
export class ApiKeyGuard implements CanActivate {
  private readonly logger = new Logger(ApiKeyGuard.name)

  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(ApiKeyVerifierService) private readonly verifier: ApiKeyVerifierService,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(BYMAX_AUTH_HOOKS) @Optional() private readonly hooks: IAuthHooks | null
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<ApiKeyRequest>()
    const required = this.declaredScopes(context)
    const base = {
      method: request.method,
      route: routePattern(request),
      requiredScopes: required ?? []
    }

    // Route configuration first, and before any credential work.
    if (required === null) {
      this.logger.error(
        `api-key: ${logSafe(request.method)} ${logSafe(base.route)} is guarded but declares no ` +
          `scopes; refused`
      )
      await this.audit(request, { ...base, outcome: 'denied', reason: 'route_undeclared' })
      throw new AuthException(AUTH_ERROR_CODES.FORBIDDEN)
    }

    let verdict: Awaited<ReturnType<ApiKeyVerifierService['verify']>>
    try {
      verdict = await this.verifier.verify(request.headers[this.options.apiKeys.header])
    } catch (err: unknown) {
      this.logger.error(`api-key: key store unavailable cause=${describeChannelStatus(err)}`)
      await this.audit(request, { ...base, outcome: 'denied', reason: 'store_error' })
      throw new AuthException(AUTH_ERROR_CODES.INTERNAL)
    }

    if (!verdict.ok) {
      await this.audit(request, { ...base, outcome: 'denied', reason: verdict.reason }, verdict.key)
      throw new AuthException(AUTH_ERROR_CODES.API_KEY_INVALID)
    }

    const { key } = verdict
    if (!required.every((scope) => key.scopes.includes(scope))) {
      await this.audit(request, { ...base, outcome: 'denied', reason: 'scope_insufficient' }, key)
      throw new AuthException(AUTH_ERROR_CODES.API_KEY_SCOPE_INSUFFICIENT)
    }

    const delivered = await this.audit(request, { ...base, outcome: 'allowed', reason: null }, key)
    // `required` audit mode: a request whose audit row could not be written is not admitted.
    if (!delivered) throw new AuthException(AUTH_ERROR_CODES.INTERNAL)

    request.apiKey = Object.freeze({
      id: key.id,
      label: key.label,
      scopes: Object.freeze([...key.scopes])
    })
    return true
  }

  /**
   * The route's scope declaration: handler over class, empty or malformed counting as none.
   *
   * @returns The scopes, or `null` when the route declares none.
   */
  private declaredScopes(context: ExecutionContext): readonly string[] | null {
    const declared = this.reflector.getAllAndOverride<unknown>(API_KEY_SCOPES_KEY, [
      context.getHandler(),
      context.getClass()
    ])
    if (
      !Array.isArray(declared) ||
      declared.length === 0 ||
      !declared.every((scope) => typeof scope === 'string')
    ) {
      return null
    }
    return declared as string[]
  }

  /**
   * Emits the audit event.
   *
   * @returns `false` only in `required` mode when the hook threw. In `best-effort` mode the hook
   *   is fired without being awaited and the result is always `true`.
   */
  private async audit(
    request: ApiKeyRequest,
    partial: {
      outcome: 'allowed' | 'denied'
      reason: ApiKeyDenyReason | null
      method: string
      route: string
      requiredScopes: readonly string[]
    },
    key: AuthApiKey | null = null
  ): Promise<boolean> {
    const hook = this.hooks?.onApiKeyRequest
    if (hook === undefined) {
      // Auditing was demanded and nothing can write it, so the request is not admitted.
      if (this.options.apiKeys.auditMode !== 'required') return true
      this.logger.error(
        'api-key: auditMode is required but no onApiKeyRequest hook is implemented; refusing'
      )
      return false
    }
    const event: ApiKeyAccessEvent = {
      ...partial,
      keyId: key?.id ?? null,
      label: key?.label ?? null,
      ip: resolveClientAddress(request)
    }
    const context = this.hookContext(request)
    const run = (): Promise<void> | void => hook.call(this.hooks, event, context)

    if (this.options.apiKeys.auditMode === 'required') {
      try {
        await run()
        return true
      } catch (err: unknown) {
        this.logger.error(`api-key: audit hook failed cause=${describeChannelStatus(err)}`)
        return false
      }
    }
    try {
      void Promise.resolve(run()).catch((err: unknown) => {
        this.logger.error(`api-key: audit hook failed cause=${describeChannelStatus(err)}`)
      })
    } catch (err: unknown) {
      this.logger.error(`api-key: audit hook failed cause=${describeChannelStatus(err)}`)
    }
    return true
  }

  private hookContext(request: ApiKeyRequest): HookContext {
    const headers = Object.fromEntries(
      Object.entries(request.headers).filter(([name]) => name !== this.options.apiKeys.header)
    )
    return {
      ip: resolveClientAddress(request),
      userAgent: request.headers['user-agent'] ?? '',
      sanitizedHeaders: sanitizeHeaders(headers)
    }
  }
}

/** The matched route pattern (`/videos/:id`), never the concrete URL; empty when none matched. */
function routePattern(request: Request): string {
  const path: unknown = (request.route as { path?: unknown } | undefined)?.path
  return typeof path === 'string' ? path : ''
}
