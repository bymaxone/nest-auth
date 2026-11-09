/**
 * @fileoverview Tests for `classifyResetProof`: which proof a reset presented, decided without
 * spending it.
 *
 * @layer Test
 */

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { classifyResetProof } from './classify-reset-proof'

function codeOf(run: () => unknown): string | undefined {
  try {
    run()
  } catch (error) {
    return ((error as AuthException).getResponse() as { error: { code: string } }).error.code
  }
  return undefined
}

const INVALID = AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID

describe('classifyResetProof', () => {
  it.each([
    ['token', { token: 't' }, { kind: 'token', value: 't' }],
    ['otp', { otp: '123456' }, { kind: 'otp', value: '123456' }],
    ['otp', { verifiedToken: 'v' }, { kind: 'verifiedToken', value: 'v' }]
  ] as const)('accepts the proof the %s method takes: %j', (method, proof, expected) => {
    expect(classifyResetProof(method, proof)).toEqual(expected)
  })

  it.each([
    ['token', {}],
    ['otp', {}],
    ['token', { otp: '123456' }],
    ['token', { verifiedToken: 'v' }],
    ['otp', { token: 't' }],
    ['token', { token: '' }],
    ['otp', { otp: '' }],
    ['otp', { verifiedToken: '' }]
  ] as const)('refuses, under the %s method, the request %j', (method, proof) => {
    expect(codeOf(() => classifyResetProof(method, proof))).toBe(INVALID)
  })

  it.each(['token', 'otp'] as const)('refuses two proofs under the %s method', (method) => {
    expect(codeOf(() => classifyResetProof(method, { token: 't', otp: '123456' }))).toBe(INVALID)
    expect(codeOf(() => classifyResetProof(method, { otp: '1', verifiedToken: 'v' }))).toBe(INVALID)
  })

  it('counts an empty proof beside a real one as two proofs', () => {
    expect(codeOf(() => classifyResetProof('token', { token: 't', otp: '' }))).toBe(INVALID)
  })
})
