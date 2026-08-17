import {
  AUTH_ERROR_CODES as SERVER_AUTH_ERROR_CODES,
  AUTH_ERROR_STATUS as SERVER_AUTH_ERROR_STATUS
} from '../../server/errors/auth-error-codes'
import {
  AUTH_ERROR_CODES as SHARED_AUTH_ERROR_CODES,
  AUTH_ERROR_STATUS as SHARED_AUTH_ERROR_STATUS
} from './error-codes'

/**
 * Drift-guard suite for the shared `AUTH_ERROR_CODES` mirror.
 *
 * The shared subpath cannot import from the server subpath at runtime
 * (it must compile in browsers), so the constants are duplicated. This
 * test file is the only place those two declarations meet — its job is
 * to fail CI the moment a code is added, removed, or renamed on one
 * side without being reflected on the other.
 *
 * Lives in the `shared` folder (not `server`) so that future
 * server-side changes immediately visualize their effect on the
 * client-facing surface.
 */
describe('shared AUTH_ERROR_CODES mirror', () => {
  // Verifies the two declarations have the exact same set of keys —
  // any addition or rename on one side without mirror update fails here.
  it('has the same keys as the server-side AUTH_ERROR_CODES', () => {
    const serverKeys = Object.keys(SERVER_AUTH_ERROR_CODES).sort()
    const sharedKeys = Object.keys(SHARED_AUTH_ERROR_CODES).sort()

    expect(sharedKeys).toEqual(serverKeys)
  })

  // Verifies every key maps to the exact same string literal on both
  // sides. Catches typos like 'auth.token_invlid' that would silently
  // miss server responses at runtime.
  it('maps every key to the exact same string value as the server', () => {
    const sharedAsRecord: Record<string, string> = SHARED_AUTH_ERROR_CODES
    const serverAsRecord: Record<string, string> = SERVER_AUTH_ERROR_CODES

    for (const key of Object.keys(serverAsRecord)) {
      expect(sharedAsRecord[key]).toBe(serverAsRecord[key])
    }
  })

  // The status map is mirrored for the same reason and needs the same guard. A code whose status
  // changes on one side only is worse than a missing code: the client keeps a mapping that looks
  // right and answers wrong, and nothing at the boundary contradicts it.
  it('maps every code to the same HTTP status as the server', () => {
    expect(SHARED_AUTH_ERROR_STATUS).toEqual(SERVER_AUTH_ERROR_STATUS)
  })

  // Asserted separately from the deep equality above, because a map missing a key and a map with
  // an extra one both fail `toEqual` with the same shape of message. This says which.
  it('covers exactly the codes the mirror declares', () => {
    expect(Object.keys(SHARED_AUTH_ERROR_STATUS).sort()).toEqual(
      Object.keys(SHARED_AUTH_ERROR_CODES)
        .map((k) => (SHARED_AUTH_ERROR_CODES as Record<string, string>)[k])
        .sort()
    )
  })
})
