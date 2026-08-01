/**
 * Unit tests for {@link CommonPasswordChecker} — the default password screen.
 *
 * The design bet is that a few hundred base words plus normalisation beats a long raw list,
 * because the published top-N lists are mostly decorated forms of a much smaller set. These
 * tests are where that bet is checked: the decorated forms have to be refused by name.
 *
 * @layer Provider
 */

import {
  COMMON_BASE_WORDS,
  CommonPasswordChecker,
  LEET_MAP,
  SEQUENCE_ALPHABETS,
  reduceToBaseWord
} from './common-password-checker.provider'
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

  // Every shipped base word, swept in one test. A sample proves the mechanism works; only the
  // full sweep proves the LIST does — a mistyped or deleted entry is otherwise invisible, and
  // the entry is the whole product here.
  //
  // Deliberately a loop inside ONE test rather than `it.each` over the array. Under `it.each`
  // the test NAME carries the datum, so corrupting an entry renames the case — and a runner
  // that selects tests by name (Stryker's per-test coverage does) then finds nothing to run and
  // reads the corruption as unnoticed. A static name keeps the assertion attached to the data.
  it('refuses every shipped base word', async () => {
    for (const word of COMMON_BASE_WORDS) {
      expect(await defaultChecker().isBreached(word)).toBe(true)
    }
  })

  // …and each entry has to survive its own normalisation, which is the invariant that makes it
  // reachable at all. `isBreached` compares `reduceToBaseWord(candidate)` against this set, so
  // an entry that does not reduce to itself can never be matched by anything: a dead line that
  // reads as a defence. `Password1` in the list would silently protect nobody.
  //
  // This is what the sweep above cannot check. That test reads the same array the
  // implementation does, so a corrupted entry is refused *because* it is in the list — the
  // assertion moves with the corruption. This one holds the entry to a rule the reduction
  // defines, not to itself.
  it('stores every base word in the reduced form it is compared in', () => {
    for (const word of COMMON_BASE_WORDS) {
      expect(reduceToBaseWord(word)).toBe(word)
      // …and long enough to clear the floor below which every candidate is refused outright,
      // where an entry would again be unreachable.
      expect(word.length).toBeGreaterThanOrEqual(4)
    }
  })

  // A duplicate is not wrong, but it is a mistake worth catching: it means an edit landed twice
  // and the second one is not the addition its author thought they were making.
  it('carries no duplicate base words', () => {
    expect(new Set(COMMON_BASE_WORDS).size).toBe(COMMON_BASE_WORDS.length)
  })

  // …and every leet substitution actually substitutes. One wrong mapping silently un-covers a
  // whole family of decorated forms — `p@ssw0rd` stops reducing to `password` — while every
  // undecorated test keeps passing.
  it('maps every leet character back to the letter it stands in for', () => {
    for (const [from, to] of LEET_MAP) {
      expect(reduceToBaseWord(`x${from}x`)).toBe(`x${to}x`)
      // The target has to be a single lowercase letter, or the substitution produces something
      // the reduction then drops — the mapping would read as configured and do nothing.
      expect(to).toMatch(/^[a-z]$/)
      // …and the source a single character that is not already the letter it maps to.
      expect(from).toHaveLength(1)
      expect(from).not.toBe(to)
    }
  })

  // …and every sequence alphabet is walked in both directions. A run is refused whatever
  // characters it is made of, which is the part no word list can enumerate.
  it('refuses a run along every sequence alphabet, in both directions', async () => {
    for (const alphabet of SEQUENCE_ALPHABETS) {
      const forwards = alphabet.slice(0, 8)
      const backwards = [...forwards].reverse().join('')

      expect(await defaultChecker().isBreached(forwards)).toBe(true)
      expect(await defaultChecker().isBreached(backwards)).toBe(true)
      // A reduced base is `[a-z0-9]+` by construction, so an alphabet carrying anything else
      // could never contain one — the entry would read as a defence and match nothing.
      expect(alphabet).toMatch(/^[a-z0-9]+$/)
      // …and it has to be long enough to hold a window that clears the four-character floor.
      expect(alphabet.length).toBeGreaterThan(8)
    }
  })

  // The reduction drops interior punctuation as well as trailing decoration, or a base word
  // would never be reached through the separators people actually type.
  it('drops interior punctuation on the way to the base word', async () => {
    expect(reduceToBaseWord('pass-word')).toBe('password')
    expect(await defaultChecker().isBreached('p.a.s.s.w.o.r.d')).toBe(true)
  })

  // The four-character floor, isolated from every other guard. `xq` survives the reduction of
  // `xq!!!!` and is not a run, not a repeat, and in no list — so only the floor refuses it, and
  // dropping the floor would let six characters of punctuation stand in for a password.
  it('refuses a candidate that reduces below the length floor and nothing else catches', async () => {
    expect(reduceToBaseWord('xq!!!!')).toBe('xq')

    expect(await defaultChecker().isBreached('xq!!!!')).toBe(true)
  })

  // The repeated-unit check is anchored at BOTH ends on purpose: it is a check on a password
  // that is nothing but padding, not on one that merely contains a repetition. Losing either
  // anchor turns it into a general "contains a repeat" rule that refuses ordinary passphrases.
  it.each([
    ['abcabcabcxylophone', 'a repeat at the front'],
    ['xylophoneabcabcabc', 'a repeat at the back'],
    ['xylophonezz', 'a doubled character at the back'],
    ['zzxylophone', 'a doubled character at the front']
  ])('allows %s (%s)', async (password) => {
    expect(await defaultChecker().isBreached(password)).toBe(false)
  })

  // The consumer's group is optional, and the provider is also usable standalone: a resolved
  // options object that carries no `password` group must not throw on construction.
  it('accepts options with no password group', async () => {
    const checker = new CommonPasswordChecker({} as unknown as ResolvedOptions)

    expect(await checker.isBreached('password')).toBe(true)
  })

  // …and an absent blocklist contributes nothing rather than some default entry — a word the
  // deployment never chose must not be refused on its behalf.
  it('adds no entry of its own when the blocklist is absent', async () => {
    expect(await checkerWith([]).isBreached('strykerwashere')).toBe(false)
    expect(await defaultChecker().isBreached('strykerwashere')).toBe(false)
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

  // The trailing decoration used to come off with `replace(/[\d\W_]+$/, '')`, which is
  // quadratic on such a run: the `$`-anchored `+` backtracks over every suffix. Unlike the
  // route-prefix trimmers, this input IS attacker-supplied — it is a candidate password. The
  // DTO bounds it at 128 characters, but that is a bound living in another file; the scan has
  // to be linear on its own.
  it('strips a long run of decoration linearly and to the same result', () => {
    expect(reduceToBaseWord('password' + '1'.repeat(500))).toBe('password')
    expect(reduceToBaseWord('password!@#_123')).toBe('password')

    const started = Date.now()
    reduceToBaseWord('a' + '!'.repeat(200_000))
    expect(Date.now() - started).toBeLessThan(1_000)
  })
})
