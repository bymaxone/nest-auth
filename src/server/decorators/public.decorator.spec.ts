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

  // Verifies that IS_PUBLIC_KEY is the string 'isPublic' as expected by JwtAuthGuard's Reflector lookup.
  it('IS_PUBLIC_KEY should be a string', () => {
    expect(typeof IS_PUBLIC_KEY).toBe('string')
    expect(IS_PUBLIC_KEY).toBe('isPublic')
  })
})
