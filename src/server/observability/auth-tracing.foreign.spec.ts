/**
 * @fileoverview A module that answers to the package name but is not the tracing API leaves the span seam
 * inert, and the operation runs bare.
 *
 * @layer Test
 */

import { AuthTracing } from './auth-tracing'

jest.mock('@opentelemetry/api', () => ({ trace: {} }))

describe('AuthTracing with a module that is not the tracing API', () => {
  // Scenario: the loaded module has no tracer factory. Expected: the seam is not armed, the operation runs once,
  // bare, with its result and its error unchanged.
  it('stays inert and runs the operation bare', async () => {
    const tracing = new AuthTracing()
    const run = jest.fn(() => Promise.resolve('bare'))
    const failure = new Error('operation failed')

    await tracing.onModuleInit()

    await expect(tracing.span('auth.login', {}, run)).resolves.toBe('bare')
    await expect(tracing.span('auth.login', {}, () => Promise.reject(failure))).rejects.toBe(
      failure
    )
    expect(run).toHaveBeenCalledTimes(1)
  })
})
