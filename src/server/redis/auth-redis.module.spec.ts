/**
 * @fileoverview Tests for AuthRedisModule, the internal NestJS module that registers
 * AuthRedisService. The module has no logic of its own — it is a @Module() class
 * that simply provides and exports AuthRedisService. This spec exists solely to
 * register the file with Jest's coverage collector so the class is counted.
 *
 * Rendering strategy: N/A — pure NestJS module class, no rendering involved.
 */

import { AuthRedisModule } from './auth-redis.module'

// ---------------------------------------------------------------------------
// AuthRedisModule — module class definition
// ---------------------------------------------------------------------------

describe('AuthRedisModule', () => {
  // Verifies that the module class is defined and importable as a constructor function.
  it('is defined as a NestJS module class', () => {
    expect(AuthRedisModule).toBeDefined()
    expect(typeof AuthRedisModule).toBe('function')
  })
})
