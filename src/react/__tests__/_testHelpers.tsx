/**
 * Shared test fixtures for the React subpath.
 *
 * Exposes:
 *   - `createMockClient()` — a jest.fn-backed stub that implements the
 *     full {@link AuthClient} interface. Each method is independently
 *     configurable via the returned mock's per-method `.mockResolvedValue`
 *     / `.mockRejectedValue` calls.
 *   - `MOCK_USER` — a realistic {@link AuthUserClient} payload.
 *   - `MOCK_AUTH_RESULT` — an {@link AuthResult} whose `.user` is
 *     {@link MOCK_USER} so provider-level `SET_USER` assertions have
 *     a stable identity to compare against.
 *   - `MOCK_MFA_RESULT` — an {@link MfaChallengeResult} for the
 *     MFA-challenge branch in `login`.
 *
 * Mocks are deliberately typed against the real `AuthClient` interface
 * so a future signature change on the client surface produces a
 * compile error in the tests — catching the drift at the seam where
 * it is cheapest to fix.
 *
 * This helper file lives under `__tests__/` and is excluded from
 * Jest's `collectCoverageFrom` by the `!**\/__tests__/**` glob in
 * `jest.config.ts`. Lint rules apply the same strict TS ruleset to
 * it as production code; the file therefore avoids `any` and keeps
 * all exports fully typed.
 */

import type { AuthClient } from '../../client'
import type { AuthResult, AuthUserClient, MfaChallengeResult } from '../../shared'

/**
 * A representative authenticated user. Values are chosen to be
 * obviously synthetic so no test accidentally asserts on a "real"
 * payload and so logs/snapshots from a failure are easy to scan.
 */
export const MOCK_USER: AuthUserClient = {
  id: 'user-uuid-1',
  email: 'user@example.test',
  name: 'Test User',
  role: 'member',
  tenantId: 'tenant-1',
  status: 'active',
  mfaEnabled: false
}

/**
 * A successful {@link AuthResult}. `accessToken` is intentionally the
 * empty string to mirror cookie-mode deployments — the bearer field
 * is unused in most tests and flagging a non-empty value could mask
 * a leak of a real token into assertions.
 */
export const MOCK_AUTH_RESULT: AuthResult = {
  user: MOCK_USER,
  accessToken: ''
}

/**
 * A representative MFA challenge. The temp token value is synthetic
 * (not a real JWT) so string-matching assertions can reason about
 * it without false positives.
 */
export const MOCK_MFA_RESULT: MfaChallengeResult = {
  mfaRequired: true,
  mfaTempToken: 'mock-mfa-temp-token'
}

/**
 * Jest-mocked instance of the {@link AuthClient} interface.
 *
 * Each property is `jest.Mock` so tests can set per-test return values
 * (`client.login.mockResolvedValueOnce(MOCK_AUTH_RESULT)`) and read
 * back call counts / arguments with the standard jest matchers.
 *
 * The `jest.Mock` types are intersected with the original method
 * signatures so mis-calling a method (wrong arity, wrong shape) fails
 * at compile time rather than with an opaque runtime error.
 */
export type MockAuthClient = {
  [K in keyof AuthClient]: jest.Mock<ReturnType<AuthClient[K]>, Parameters<AuthClient[K]>>
}

/**
 * Build a fresh {@link MockAuthClient} where every method is a
 * jest.fn() with no default return. Tests must set the return value
 * for each method they exercise — unconfigured methods return
 * `undefined`, which surfaces missing configuration loudly.
 */
export function createMockClient(): MockAuthClient {
  return {
    login: jest.fn(),
    register: jest.fn(),
    logout: jest.fn(),
    refresh: jest.fn(),
    getMe: jest.fn(),
    mfaChallenge: jest.fn(),
    forgotPassword: jest.fn(),
    resetPassword: jest.fn()
  }
}
