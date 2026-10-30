/**
 * @fileoverview A request with no body reaches every body route as an object.
 *
 * `ValidationPipe` validates an empty object in place of a missing body, then hands the handler
 * the ORIGINAL `undefined` (`if (isNil) return originalValue`, transform off). A DTO with a
 * required field already refuses that empty object; a DTO whose fields are all optional passes
 * it and the handler dereferences `undefined`. This walks every body route the module can mount,
 * so a DTO added later with only optional fields is caught here rather than by a 500 in
 * production.
 */
import { ROUTE_ARGS_METADATA } from '@nestjs/common/constants'
import { RouteParamtypes } from '@nestjs/common/enums/route-paramtypes.enum'
import type { PipeTransform, Type } from '@nestjs/common'

import { AUTH_CONTROLLERS } from '../bymax-auth.module'

interface BodyRoute {
  label: string
  run: (value: unknown) => Promise<unknown>
}

/** Every body parameter of every mountable controller, with the pipes that run on it. */
function bodyRoutes(): BodyRoute[] {
  const routes: BodyRoute[] = []
  for (const controller of AUTH_CONTROLLERS as Array<Type<object>>) {
    const classPipes = (Reflect.getMetadata('__pipes__', controller) ?? []) as PipeTransform[]
    for (const handler of Object.getOwnPropertyNames(controller.prototype)) {
      if (handler === 'constructor') continue
      const args = Reflect.getMetadata(ROUTE_ARGS_METADATA, controller, handler) as
        Record<string, { index: number }> | undefined
      const types = Reflect.getMetadata('design:paramtypes', controller.prototype, handler) as
        Array<Type<object>> | undefined
      if (args === undefined || types === undefined) continue
      const methodPipes = (Reflect.getMetadata(
        '__pipes__',
        (controller.prototype as Record<string, object>)[handler] as object
      ) ?? []) as PipeTransform[]
      for (const [key, { index }] of Object.entries(args)) {
        if (Number(key.split(':')[0]) !== RouteParamtypes.BODY) continue
        const metatype = types[index] as Type<object>
        routes.push({
          label: `${controller.name}.${handler} (${metatype.name})`,
          run: async (value) => {
            let out = value
            for (const pipe of [...classPipes, ...methodPipes]) {
              out = await pipe.transform(out, { type: 'body', metatype })
            }
            return out
          }
        })
      }
    }
  }
  return routes
}

describe('a missing body on a body route', () => {
  const routes = bodyRoutes()

  // Scenario: the walker itself. Expected: it finds the body routes the module mounts. Why: a
  // walker that silently finds none would turn every case below into a vacuous pass.
  it('finds the mounted body routes', () => {
    expect(routes.length).toBeGreaterThanOrEqual(24)
  })

  // Scenario: an absent body (`undefined`) and a `null` body on each route. Expected: the pipe
  // either refuses it or hands the handler an object. Why: a nil value reaching a handler that
  // reads `dto.field` is a TypeError, which a client sees as a 500 for a mistake that is theirs.
  describe.each([
    ['undefined', undefined],
    ['null', null]
  ])('%s body', (_name, body) => {
    it.each(routes.map((r) => [r.label, r] as const))('%s', async (_label, route) => {
      let out: unknown
      let refused = false
      try {
        out = await route.run(body)
      } catch {
        refused = true
      }

      expect(refused || (typeof out === 'object' && out !== null)).toBe(true)
    })
  })
})
