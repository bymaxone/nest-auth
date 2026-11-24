/**
 * @fileoverview The call of a repository method of the host goes through a reference taken at load, so a replaced
 * `Function.prototype.apply` cannot answer for the repository.
 *
 * @layer Test
 */

import { guardRepository } from './host-read'
import type { ErasedRepositoryContract } from './repository-contracts'

const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor

const ANSWERS: ErasedRepositoryContract = { find: { fields: { id: '~id' }, nested: {} } }

describe('a repository method of the host while Function.prototype.apply is replaced', () => {
  // Scenario: `apply` is replaced by a function that answers a forged record for the repository's method and puts the original back.
  // Expected: the answer is the one the repository gave. Why: the replacement erased itself, so no later root check can see it.
  it('answers what the repository returned', async () => {
    const held = getOwn(Function.prototype, 'apply') as PropertyDescriptor
    // The repository puts `apply` back as it answers, so the guard at the return sees a root that is clean again.
    const repository = {
      find: async (): Promise<unknown> => {
        define(Function.prototype, 'apply', held)
        return { id: 'stored' }
      }
    }
    const guarded = guardRepository(repository, ANSWERS)
    define(Function.prototype, 'apply', {
      ...held,
      value: function forge(this: unknown, ...args: unknown[]): unknown {
        if (this !== repository.find) return Reflect.apply(held.value as () => unknown, this, args)
        define(Function.prototype, 'apply', held)
        return Promise.resolve({ id: 'forged' })
      }
    })
    let answer: unknown
    try {
      answer = await guarded.find()
    } finally {
      define(Function.prototype, 'apply', held)
    }

    expect(answer).toEqual({ id: 'stored' })
  })
})
