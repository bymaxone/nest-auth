/**
 * PlatformRolesDecorator — unit tests
 *
 * Tests the @PlatformRoles decorator and its associated PLATFORM_ROLES_KEY symbol.
 *
 * The decorator uses NestJS's SetMetadata() internally, which relies on the
 * reflect-metadata API to attach metadata to targets. Tests use Reflect.getMetadata
 * to verify the stored values without going through NestJS internals.
 *
 * reflect-metadata is imported at the top to ensure the Reflect global is available
 * in the Node.js test environment (ts-jest does not auto-import it).
 */

import 'reflect-metadata'

import { PLATFORM_ROLES_KEY, PlatformRoles } from './platform-roles.decorator'

// ---------------------------------------------------------------------------
// PLATFORM_ROLES_KEY — symbol identity
// ---------------------------------------------------------------------------

describe('PLATFORM_ROLES_KEY', () => {
  // The key must be a Symbol so it is unique and cannot collide with string-based
  // metadata keys used elsewhere in the application.
  it('should be a Symbol', () => {
    expect(typeof PLATFORM_ROLES_KEY).toBe('symbol')
  })

  // Two calls to Symbol('platformRoles') would produce different symbols.
  // This test guards against accidental re-creation: the exported constant
  // must always be the same reference. Assigning to a local variable and
  // comparing with strict equality verifies the reference is stable.
  it('should be a stable reference (not re-created on each use)', () => {
    const ref1 = PLATFORM_ROLES_KEY
    const ref2 = PLATFORM_ROLES_KEY
    expect(ref1).toBe(ref2)
    expect(ref1).toBe(PLATFORM_ROLES_KEY)
  })
})

// ---------------------------------------------------------------------------
// PlatformRoles — decorator factory
// ---------------------------------------------------------------------------

describe('PlatformRoles', () => {
  // The decorator factory must return a function (both MethodDecorator and ClassDecorator
  // are functions in TypeScript's type system) that can be applied to targets.
  it('should return a function when called with role arguments', () => {
    expect(typeof PlatformRoles('admin')).toBe('function')
  })

  // PlatformRoles() with no arguments is valid: it means "requires no specific role"
  // (effectively treated as an open route by PlatformRolesGuard). The factory must
  // still return a function without throwing.
  it('should return a function when called with no arguments', () => {
    expect(typeof PlatformRoles()).toBe('function')
  })

  // ---------------------------------------------------------------------------
  // Class decorator — metadata stored on the class constructor
  // ---------------------------------------------------------------------------

  describe('applied as a class decorator', () => {
    // When @PlatformRoles('admin') is applied to a class, Reflect.getMetadata must
    // return ['admin'] from the class constructor using PLATFORM_ROLES_KEY.
    it('should store a single role in class metadata', () => {
      @PlatformRoles('admin')
      class TestController {}

      const stored = Reflect.getMetadata(PLATFORM_ROLES_KEY, TestController)
      expect(stored).toEqual(['admin'])
    })

    // Multiple roles passed to the factory must all be stored in the metadata array.
    it('should store multiple roles in class metadata', () => {
      @PlatformRoles('super_admin', 'admin')
      class TestController {}

      const stored = Reflect.getMetadata(PLATFORM_ROLES_KEY, TestController)
      expect(stored).toEqual(['super_admin', 'admin'])
    })

    // PlatformRoles() with no arguments stores an empty array; PlatformRolesGuard
    // treats this as no restriction and allows all platform tokens through.
    it('should store an empty array in class metadata when called with no arguments', () => {
      @PlatformRoles()
      class TestController {}

      const stored = Reflect.getMetadata(PLATFORM_ROLES_KEY, TestController)
      expect(stored).toEqual([])
    })
  })

  // ---------------------------------------------------------------------------
  // Method decorator — metadata stored on the method function itself
  // ---------------------------------------------------------------------------

  describe('applied as a method decorator', () => {
    // NestJS SetMetadata stores method-level metadata on the method function itself
    // (i.e. prototype.methodName), not as a keyed property on the prototype.
    // Retrievable via Reflect.getMetadata(KEY, prototype.methodName).
    it('should store roles in method metadata', () => {
      class TestController {
        @(PlatformRoles('support') as MethodDecorator)
        listUsers(): void {
          return
        }
      }

      const stored = Reflect.getMetadata(PLATFORM_ROLES_KEY, TestController.prototype.listUsers)
      expect(stored).toEqual(['support'])
    })

    // Two separate methods decorated with different roles must not share metadata.
    // Each method function carries its own metadata object.
    it('should store independent metadata on each decorated method', () => {
      class TestController {
        @(PlatformRoles('super_admin') as MethodDecorator)
        deleteUser(): void {
          return
        }

        @(PlatformRoles('support') as MethodDecorator)
        viewLogs(): void {
          return
        }
      }

      const deleteStored = Reflect.getMetadata(
        PLATFORM_ROLES_KEY,
        TestController.prototype.deleteUser
      )
      const viewStored = Reflect.getMetadata(PLATFORM_ROLES_KEY, TestController.prototype.viewLogs)

      expect(deleteStored).toEqual(['super_admin'])
      expect(viewStored).toEqual(['support'])
    })
  })
})
