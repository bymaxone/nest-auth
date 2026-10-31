import { Logger } from '@nestjs/common'

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
    expect(runDetached(logger, run, 'effect failed')).toBeUndefined()
    await drain()
    expect(run).toHaveBeenCalledTimes(1)
    expect(error).not.toHaveBeenCalled()
  })

  // The caller is never held up by a slow effect.
  it('returns before a pending effect settles', () => {
    runDetached(logger, () => new Promise(() => undefined), 'effect failed')
    expect(error).not.toHaveBeenCalled()
  })

  // A rejection and a synchronous throw are both caught, and both log the label and the SHAPE
  // of the error — never the text the failing party wrote.
  it.each([
    ['a rejection', () => Promise.reject(new Error('secret=ABC123'))],
    [
      'a synchronous throw',
      () => {
        throw new Error('secret=ABC123')
      }
    ]
  ])('logs %s under the label without the error text', async (_name, run) => {
    runDetached(logger, run, 'effect failed')
    await drain()
    expect(error).toHaveBeenCalledTimes(1)
    const line = String(error.mock.calls[0]?.[0])
    expect(line.startsWith('effect failed: ')).toBe(true)
    expect(line).not.toContain('ABC123')
  })
})
