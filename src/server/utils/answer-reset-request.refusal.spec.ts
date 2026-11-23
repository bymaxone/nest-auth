/**
 * @fileoverview The refusal of the library raised while a reset is issued is not logged as a store failure: it is raised to the
 * caller once the floor has been paid, and nothing says the store failed.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { answerResetRequest } from './answer-reset-request'
import { assertRootIsStandard } from './object-prototype-guard'

// The test's own copies: the window below replaces a built-in, so nothing inside it may call a live one.
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor

/** Makes the refusal of the library by calling its check while a built-in is replaced. */
function makeRefusal(): unknown {
  const held = getOwn(Array.prototype, 'every') as PropertyDescriptor
  define(Array.prototype, 'every', { ...held, value: () => true })
  try {
    assertRootIsStandard()
  } catch (error) {
    return error
  } finally {
    define(Array.prototype, 'every', held)
  }
  return undefined
}

describe('answerResetRequest and a refusal of the library', () => {
  // Scenario: issuing the reset fails with the refusal of the library. Expected: the refusal is raised and no store failure is
  // logged. Why: the store did not fail, so an operator must not be sent to look at it.
  it('raises the refusal without logging a store failure', async () => {
    const refusal = makeRefusal()
    const logger = new Logger('answer-reset-request-refusal-test')
    const error = jest.spyOn(logger, 'error').mockImplementation(() => undefined)
    const redis = {
      setnx: jest.fn().mockResolvedValue(true),
      del: jest.fn().mockResolvedValue(true)
    }

    await expect(
      answerResetRequest({ redis, logger } as never, {
        cooldownKey: 'cooldown:k',
        cooldownSeconds: 60,
        floorMs: 0,
        start: Date.now(),
        findAccount: async () => ({ id: 'user-1', status: 'ACTIVE' }),
        isBlocked: () => false,
        issue: async () => {
          throw refusal
        }
      })
    ).rejects.toBe(refusal)
    expect(error).not.toHaveBeenCalled()
  })
})
