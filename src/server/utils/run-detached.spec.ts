import { Logger } from '@nestjs/common'

import { eventOf } from '../__tests__/log-events'
import { runDetached } from './run-detached'

describe('runDetached', () => {
  const logger = new Logger('Test')
  let error: jest.SpyInstance

  beforeEach(() => {
    error = jest.spyOn(logger, 'error').mockImplementation(() => undefined)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  const drain = async (): Promise<void> => {
    await Promise.resolve()
    await Promise.resolve()
  }

  // The effect runs, nothing is logged, and nothing is returned for the caller to wait on.
  it('runs the effect and logs nothing when it succeeds', async () => {
    const run = jest.fn().mockResolvedValue(undefined)
    expect(runDetached(logger, run, 'afterLogin')).toBeUndefined()
    await drain()
    expect(run).toHaveBeenCalledTimes(1)
    expect(error).not.toHaveBeenCalled()
  })

  // The caller is never held up by a slow effect.
  it('returns before a pending effect settles', () => {
    runDetached(logger, () => new Promise(() => undefined), 'afterLogin')
    expect(error).not.toHaveBeenCalled()
  })

  // A rejection and a synchronous throw are both caught, and the event carries the hook and how it
  // failed, never the text the failing party wrote.
  it.each([
    ['a rejection', () => Promise.reject(new Error('secret=ABC123')), 'rejected'],
    [
      'a synchronous throw',
      () => {
        throw new Error('secret=ABC123')
      },
      'threw'
    ]
  ])('logs %s as a failed hook without the error text', async (_name, run, how) => {
    runDetached(logger, run, 'afterLogin')
    await drain()
    expect(error).toHaveBeenCalledTimes(1)
    expect(error).toHaveBeenCalledWith(eventOf('AUTH_HOOK_FAILED', { hook: 'afterLogin', how }))
    expect(JSON.stringify(error.mock.calls)).not.toContain('ABC123')
  })
})
