/**
 * Unit tests for {@link CommonPasswordChecker} — the default password screen.
 *
 * The design bet is that a few hundred base words plus normalisation beats a long raw list,
 * because the published top-N lists are mostly decorated forms of a much smaller set. These
 * tests are where that bet is checked: the decorated forms have to be refused by name.
 *
 * @layer Provider
 */

import { CommonPasswordChecker, reduceToBaseWord } from './common-password-checker.provider'
import type { ResolvedOptions } from '../config/resolved-options'

/** A checker with no consumer-supplied blocklist — the shipped default. */
function defaultChecker(): CommonPasswordChecker {
  return new CommonPasswordChecker()
}

/** A checker carrying the deployment's own context words. */
function checkerWith(blocklist: readonly string[]): CommonPasswordChecker {
  return new CommonPasswordChecker({ password: { blocklist } } as unknown as ResolvedOptions)
}

describe('reduceToBaseWord', () => {
  // The reduction is the whole mechanism: one base entry has to stand in for the family of
  // decorated forms a raw list would need to spell out one at a time.
  it.each([
    ['password', 'password'],
    ['Password', 'password'],
    ['PASSWORD', 'password'],
    ['Password1', 'password'],
    ['password123', 'password'],
    ['P@ssw0rd', 'password'],
    ['p@$$w0rd!', 'password'],
    ['Password2024!', 'password'],
    ['pa55word', 'password']
  ])('reduces %s to %s', (input, expected) => {
    expect(reduceToBaseWord(input)).toBe(expected)
  })

  // Only TRAILING decoration comes off. A leading digit is part of the word, so `1password`
  // must not collapse onto `password` — over-blocking is its own failure.
  it('does not reduce a leading digit away', () => {
    expect(reduceToBaseWord('1password')).not.toBe('password')
  })

  // Nothing but decoration reduces to nothing, which the checker treats as "there was no
  // password here".
  it.each([['12345678'], ['!!!!!!!!'], ['20242024']])('reduces %s to the empty string', (input) => {
    expect(reduceToBaseWord(input)).toBe('')
  })
})

describe('CommonPasswordChecker', () => {
  // The entries every published list opens with. Before this checker was the default, a
  // deployment on defaults accepted every one of them.
  it.each([
    ['password'],
    ['Password1'],
    ['P@ssw0rd'],
    ['password123'],
    ['qwertyui'],
    ['qwerty123'],
    ['iloveyou'],
    ['sunshine'],
    ['football'],
    ['superman'],
    ['michael1'],
    ['letmein123'],
    ['welcome1'],
    ['changeme'],
    ['administrator'],
    ['trustno1']
  ])('refuses %s', async (password) => {
    expect(await defaultChecker().isBreached(password)).toBe(true)
  })

  // Structural weakness no word list can enumerate: a run, a repeat, or a short unit padded
  // out to reach the length floor.
  it.each([
    ['12345678', 'a digit run'],
    ['87654321', 'a digit run backwards'],
    ['abcdefgh', 'an alphabet run'],
    ['aaaaaaaa', 'one character repeated'],
    ['abcabcabc', 'a unit repeated'],
    ['1212121212', 'a pair repeated'],
    ['!!!!!!!!', 'punctuation only'],
    ['a1234567', 'one letter padded with digits'],
    ['abc12345', 'a fragment padded with digits']
  ])('refuses %s (%s)', async (password) => {
    expect(await defaultChecker().isBreached(password)).toBe(true)
  })

  // The check must not become a general complexity rule. A password with no relation to the
  // bases and no structural pattern passes, whatever it looks like.
  it.each([
    ['correct-horse-battery-staple'],
    ['Tr0ub4dor&3xyz'],
    ['gliding-walnut-forecast'],
    ['9fK2mQwZ'],
    ['1password']
  ])('allows %s', async (password) => {
    expect(await defaultChecker().isBreached(password)).toBe(false)
  })

  // ASVS v5 §6.2.11: the deployment's own product, company and domain names — the words its
  // users reach for first, and which no general corpus contains.
  it('refuses a consumer-supplied context word', async () => {
    const checker = checkerWith(['Acme'])

    expect(await checker.isBreached('acme')).toBe(true)
    // …and its decorated forms, without anyone having to list them.
    expect(await checker.isBreached('Acme2024!')).toBe(true)
    expect(await checker.isBreached('@cme123')).toBe(true)
  })

  // A consumer word must not leak into the shipped set for other deployments, and the shipped
  // set must still apply alongside it.
  it('keeps the shipped bases when a blocklist is supplied', async () => {
    const checker = checkerWith(['acme'])

    expect(await checker.isBreached('Password1')).toBe(true)
    expect(await defaultChecker().isBreached('acme')).toBe(false)
  })

  // The provider is constructed by Nest with the resolved options; an absent group must not
  // throw, since the checker is also usable standalone.
  it('works without any options', async () => {
    expect(await new CommonPasswordChecker(undefined).isBreached('password')).toBe(true)
  })
})
