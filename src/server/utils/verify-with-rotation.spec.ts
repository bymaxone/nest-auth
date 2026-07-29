/**
 * @fileoverview Unit tests for {@link verifyWithRotation}.
 *
 * The property under test is that a rotation is a rollout, not a mass logout: a token signed
 * under the retired secret keeps verifying while it drains, nothing is ever signed under one,
 * and a token no secret accepts fails exactly the way it failed before rotation existed.
 */

import { JwtService } from '@nestjs/jwt'

import { verifyWithRotation } from './verify-with-rotation'

import type { ResolvedOptions } from '../config/resolved-options'

const CURRENT = 'c'.repeat(48)
const RETIRED = 'r'.repeat(48)
const OLDER = 'o'.repeat(48)

/** Options carrying the given retired secrets, if any. */
function optionsWith(previousSecrets?: string[]): ResolvedOptions {
  return {
    jwt: { algorithm: 'HS256', ...(previousSecrets === undefined ? {} : { previousSecrets }) }
  } as unknown as ResolvedOptions
}

/** A service that signs and verifies under `secret`. */
function serviceFor(secret: string): JwtService {
  return new JwtService({ secret, signOptions: { expiresIn: '5m' } })
}

describe('verifyWithRotation', () => {
  // Scenario: an ordinary token under the current secret. Expected: verified on the first try.
  // Why: the common path must not pay for a feature nobody has switched on.
  it('should verify under the current secret without consulting the retired ones', () => {
    const jwt = serviceFor(CURRENT)
    const spy = jest.spyOn(jwt, 'verify')
    const token = jwt.sign({ sub: 'u1' })

    expect(verifyWithRotation<{ sub: string }>(jwt, optionsWith([RETIRED]), token).sub).toBe('u1')
    expect(spy).toHaveBeenCalledTimes(1)
  })

  // Scenario: a token signed before the rotation, presented after it. Expected: verified.
  // Why: this is the entire point. Without it, rolling a new secret signs every user out at
  // the moment the deployment goes live.
  it('should verify a token signed under a retired secret', () => {
    const oldService = serviceFor(RETIRED)
    const token = oldService.sign({ sub: 'u2' })
    const jwt = serviceFor(CURRENT)

    expect(verifyWithRotation<{ sub: string }>(jwt, optionsWith([RETIRED]), token).sub).toBe('u2')
  })

  // Scenario: two rotations in flight, the token from the older one. Expected: verified — every
  // listed secret is tried, in order.
  it('should walk the whole list of retired secrets', () => {
    const token = serviceFor(OLDER).sign({ sub: 'u3' })
    const jwt = serviceFor(CURRENT)

    expect(verifyWithRotation<{ sub: string }>(jwt, optionsWith([RETIRED, OLDER]), token).sub).toBe(
      'u3'
    )
  })

  // Scenario: a token under a secret nobody holds. Expected: throws, and throws the CURRENT
  // secret's failure. Why: reporting which secret failed would tell an attacker whether a
  // forgery was made under a key the deployment used to hold.
  it('should throw the current failure when no secret accepts the token', () => {
    const token = serviceFor('z'.repeat(48)).sign({ sub: 'nope' })
    const jwt = serviceFor(CURRENT)

    expect(() => verifyWithRotation(jwt, optionsWith([RETIRED, OLDER]), token)).toThrow(
      'invalid signature'
    )
  })

  // Scenario: no rotation configured — the ordinary case. Expected: a bad token still throws,
  // and the absent list is not a crash.
  it('should behave exactly as before when no rotation is configured', () => {
    const jwt = serviceFor(CURRENT)
    const good = jwt.sign({ sub: 'u4' })
    const bad = serviceFor(RETIRED).sign({ sub: 'u5' })

    expect(verifyWithRotation<{ sub: string }>(jwt, optionsWith(), good).sub).toBe('u4')
    expect(() => verifyWithRotation(jwt, optionsWith(), bad)).toThrow()
    expect(() => verifyWithRotation(jwt, optionsWith([]), bad)).toThrow()
  })

  // Scenario: an expired token signed under a retired secret. Expected: still rejected. Why: a
  // retired secret buys a token nothing but signature acceptance — every other check the
  // verifier makes still applies, or a rotation would quietly extend token lifetimes.
  it('should not let a retired secret excuse an expired token', () => {
    const expired = new JwtService({ secret: RETIRED }).sign(
      { sub: 'u6' },
      { expiresIn: '-1s' as unknown as number }
    )
    const jwt = serviceFor(CURRENT)

    expect(() => verifyWithRotation(jwt, optionsWith([RETIRED]), expired)).toThrow()
  })

  // Scenario: the algorithm the options pin. Expected: forwarded on every attempt, retired ones
  // included. Why: a rotation that dropped the pin would reopen algorithm confusion on exactly
  // the path least likely to be tested.
  it('should pin the algorithm on the retired attempts too', () => {
    const jwt = serviceFor(CURRENT)
    const spy = jest.spyOn(jwt, 'verify')
    const token = serviceFor(RETIRED).sign({ sub: 'u7' })

    verifyWithRotation(jwt, optionsWith([RETIRED]), token)

    for (const call of spy.mock.calls) {
      expect((call[1] as { algorithms: string[] }).algorithms).toEqual(['HS256'])
    }
  })
})
