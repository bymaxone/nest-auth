/**
 * @fileoverview Fails startup when a route declares a scope outside the configured vocabulary.
 *
 * @layer Service
 */

import { Inject, Injectable } from '@nestjs/common'
import type { OnApplicationBootstrap } from '@nestjs/common'
import { DiscoveryService, MetadataScanner, Reflector } from '@nestjs/core'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { API_KEY_SCOPES_KEY } from '../decorators/api-key-scopes.decorator'

/**
 * Walks every controller once at bootstrap and refuses a declaration the vocabulary does not
 * contain.
 *
 * Without it a typo (`@ServiceKey('raed')`) is only found at runtime, as a route that refuses
 * every key. Declaring nothing at all is NOT an error here: that is the guard's fail-closed
 * branch and is reported per request.
 */
@Injectable()
export class ApiKeyScopeAuditService implements OnApplicationBootstrap {
  constructor(
    @Inject(DiscoveryService) private readonly discovery: DiscoveryService,
    @Inject(MetadataScanner) private readonly scanner: MetadataScanner,
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions
  ) {}

  /** @throws {Error} Naming every route that declares a scope the vocabulary lacks. */
  onApplicationBootstrap(): void {
    const vocabulary = new Set(this.options.apiKeys.scopes)
    const problems: string[] = []

    for (const wrapper of this.discovery.getControllers()) {
      const { instance, metatype } = wrapper
      if (!instance || typeof metatype !== 'function') continue

      this.collect(
        problems,
        vocabulary,
        metatype.name,
        this.reflector.get(API_KEY_SCOPES_KEY, metatype)
      )
      const prototype: object = Object.getPrototypeOf(instance) as object
      for (const method of this.scanner.getAllMethodNames(prototype)) {
        // `getAllMethodNames` returns function members only, so this is a method.
        const handler = (prototype as Record<string, () => void>)[method] as () => void
        this.collect(
          problems,
          vocabulary,
          `${metatype.name}.${method}`,
          this.reflector.get(API_KEY_SCOPES_KEY, handler)
        )
      }
    }

    if (problems.length > 0) {
      throw new Error(
        `[BymaxAuthModule] ${problems.join('; ')}. Add the scope to apiKeys.scopes or correct the ` +
          `declaration.`
      )
    }
  }

  private collect(
    problems: string[],
    vocabulary: ReadonlySet<string>,
    where: string,
    declared: unknown
  ): void {
    if (!Array.isArray(declared)) return
    for (const scope of declared) {
      // The vocabulary holds only strings, so `has` also refuses a non-string entry.
      if (!vocabulary.has(scope as string)) {
        problems.push(`${where} declares a scope outside apiKeys.scopes`)
        return
      }
    }
  }
}
