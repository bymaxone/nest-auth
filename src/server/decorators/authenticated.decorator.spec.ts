import { Reflector } from '@nestjs/core'

import { Authenticated } from './authenticated.decorator'
import { IS_PUBLIC_KEY, Public } from './public.decorator'

describe('Authenticated decorator', () => {
  // The whole point of the decorator is the VALUE it writes. `false` undoes a class-level
  // `@Public()`; `true` would be a second way of spelling `@Public()` — a decorator named
  // "authenticated" that exempts the route from authentication, on a route that reads as
  // protected. Nothing else in the system would notice, because the guard returns early
  // either way and the route still mounts and still answers.
  it('should set IS_PUBLIC_KEY metadata to false on the target', () => {
    class TestController {
      @(Authenticated() as MethodDecorator)
      testMethod() {}
    }

    const metadata: unknown = Reflect.getMetadata(
      IS_PUBLIC_KEY,
      TestController.prototype.testMethod
    )

    expect(metadata).toBe(false)
    expect(metadata).not.toBe(true)
  })

  // …and it has to win over a class-level `@Public()`, which is the only reason it exists.
  // The guards resolve the flag with `getAllAndOverride([handler, class])`, so this asserts
  // the resolution a guard actually performs rather than the raw metadata alone.
  it('overrides a class-level @Public() for the handler it decorates', () => {
    @(Public() as ClassDecorator)
    class PublicController {
      @(Authenticated() as MethodDecorator)
      protectedMethod() {}

      openMethod() {}
    }

    const reflector = new Reflector()

    expect(
      reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
        PublicController.prototype.protectedMethod,
        PublicController
      ])
    ).toBe(false)
    // …while every other handler on the same controller stays exempt, or the decorator would
    // be silently protecting routes its author never touched.
    expect(
      reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
        PublicController.prototype.openMethod,
        PublicController
      ])
    ).toBe(true)
  })
})
