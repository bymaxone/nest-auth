/**
 * @fileoverview The token verifier reports the library's own refusal as it is while a key is planted on `Object.prototype`, and a
 * token that does not verify as an invalid token.
 *
 * @layer Test
 */

import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AccountStatusService } from './account-status.service'
import { AuthRevocationService } from './auth-revocation.service'
import { AuthTokenVerifierService } from './auth-token-verifier.service'

const jwt = { verify: jest.fn() }

describe('AuthTokenVerifierService while a key is planted on Object.prototype', () => {
  let verifier: AuthTokenVerifierService

  beforeEach(async () => {
    jest.resetAllMocks()
    const module = await Test.createTestingModule({
      providers: [
        AuthTokenVerifierService,
        { provide: JwtService, useValue: jwt },
        {
          provide: BYMAX_AUTH_OPTIONS,
          useValue: { jwt: { algorithm: 'HS256', previousSecrets: [] } }
        },
        { provide: AuthRevocationService, useValue: {} },
        { provide: AccountStatusService, useValue: {} }
      ]
    }).compile()
    verifier = module.get(AuthTokenVerifierService)
  })

  const codeOf = async (): Promise<unknown> => {
    const failure = await verifier
      .verifyAccessToken('tok', { plane: 'dashboard' })
      .catch((error: unknown) => error)
    return ((failure as AuthException).getResponse() as { error: { code: string } }).error.code
  }

  // Scenario: a token that does not verify, with nothing planted and then with a key planted. Expected: the first is an invalid token
  // and the second is the library's refusal. Why: a polluted process must not look like every client being signed out.
  it('answers auth.internal, not auth.token_invalid, while a key is planted', async () => {
    jwt.verify.mockImplementation(() => {
      throw new Error('jwt expired')
    })

    expect(await codeOf()).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
    Object.defineProperty(Object.prototype, 'sessions', {
      value: 'planted',
      configurable: true,
      enumerable: true,
      writable: true
    })
    try {
      expect(await codeOf()).toBe(AUTH_ERROR_CODES.INTERNAL)
    } finally {
      Reflect.deleteProperty(Object.prototype, 'sessions')
    }
  })
})
