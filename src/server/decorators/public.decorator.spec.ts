import { Reflector } from '@nestjs/core'

import { IS_PUBLIC_KEY, Public } from './public.decorator'

describe('Public decorator', () => {
  // Verifies that applying @Public() sets IS_PUBLIC_KEY metadata to true on the decorated method.
  it('should set IS_PUBLIC_KEY metadata to true on the target', () => {
    class TestController {
      @(Public() as MethodDecorator)
      testMethod() {}
    }

    const reflector = new Reflector()
    const metadata = Reflect.getMetadata(IS_PUBLIC_KEY, TestController.prototype.testMethod)
    expect(metadata).toBe(true)
  })

  // A `Symbol`, not the string `'isPublic'`. That literal is the one the canonical NestJS
  // documentation uses in its own `@Public()` example, so a host following those docs wrote the
  // SAME metadata key — and every route it marked public for its own guard was then also public
  // to `JwtAuthGuard` wherever the host mounts it. Both decorators mean "skip auth", so nobody's
  // intent was inverted, but a key that gates authentication should not be a value the
  // ecosystem hands out by convention. `SKIP_MFA_KEY` already made this call.
  it('IS_PUBLIC_KEY is a unique Symbol rather than a conventional string', () => {
    expect(typeof IS_PUBLIC_KEY).toBe('symbol')
    // Not registered in the global symbol registry either, so `Symbol.for('bymax:isPublic')`
    // in a consumer cannot reach it.
    expect(Symbol.keyFor(IS_PUBLIC_KEY)).toBeUndefined()
    expect(IS_PUBLIC_KEY.description).toBe('bymax:isPublic')
    expect(IS_PUBLIC_KEY).not.toBe('isPublic')
  })
})
