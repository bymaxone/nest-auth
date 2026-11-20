/**
 * @fileoverview Without the optional package the span seam stays inert and the operation runs bare.
 *
 * @layer Test
 */

import { AuthTracing } from './auth-tracing'

jest.mock('@opentelemetry/api', () => {
  throw new Error("Cannot find module '@opentelemetry/api'")
})

describe('AuthTracing without @opentelemetry/api', () => {
  // Scenario: the package cannot be loaded. Expected: start-up does not fail, and the operation runs once,
  // bare, with its result and its error unchanged.
  it('loads quietly and runs the operation bare', async () => {
    const tracing = new AuthTracing()
    const run = jest.fn(() => Promise.resolve('bare'))
    const failure = new Error('operation failed')

    await expect(tracing.onModuleInit()).resolves.toBeUndefined()
    await expect(tracing.span('auth.login', {}, run)).resolves.toBe('bare')
    await expect(tracing.span('auth.login', {}, () => Promise.reject(failure))).rejects.toBe(
      failure
    )

    expect(run).toHaveBeenCalledTimes(1)
  })
})
