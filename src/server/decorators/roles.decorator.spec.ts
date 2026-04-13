import { ROLES_KEY, Roles } from './roles.decorator'

describe('Roles decorator', () => {
  // Verifies that applying @Roles('admin', 'owner') stores the full roles array under ROLES_KEY metadata.
  it('should set ROLES_KEY metadata with the specified roles', () => {
    class TestController {
      @(Roles('admin', 'owner') as MethodDecorator)
      testMethod() {}
    }

    const metadata = Reflect.getMetadata(ROLES_KEY, TestController.prototype.testMethod)
    expect(metadata).toEqual(['admin', 'owner'])
  })

  // Verifies that applying @Roles with a single role stores a single-element array.
  it('should set single role', () => {
    class TestController {
      @(Roles('member') as MethodDecorator)
      testMethod() {}
    }

    const metadata = Reflect.getMetadata(ROLES_KEY, TestController.prototype.testMethod)
    expect(metadata).toEqual(['member'])
  })

  // Verifies that ROLES_KEY is the string 'roles' as expected by RolesGuard's Reflector lookup.
  it('ROLES_KEY should be a string', () => {
    expect(typeof ROLES_KEY).toBe('string')
    expect(ROLES_KEY).toBe('roles')
  })
})
