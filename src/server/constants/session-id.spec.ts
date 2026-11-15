import { sessionId } from './session-id'

describe('sessionId', () => {
  const SID = '4d6e1c2a-8b3f-4a5e-9c7d-0e1f2a3b4c5d'

  // Scenario: a family id in the contract's shape. Expected: returned as it is.
  it('returns a value in the contract shape unchanged', () => {
    expect(sessionId(SID)).toBe(SID)
  })

  // Scenario: values that are not a session id this library minted. Expected: absent.
  // Why: a token must never name a session it cannot prove, and a caller-shaped value must not
  // steer the key the mark is read under.
  it.each([
    undefined,
    null,
    '',
    42,
    {},
    ['x'],
    'fam-old-1',
    SID.toUpperCase(),
    `${SID}:x`,
    ` ${SID}`,
    `${SID}\n`,
    SID.slice(1),
    SID.replace(/-/g, '')
  ])('reads %j as absent', (value) => {
    expect(sessionId(value)).toBeUndefined()
  })
})
