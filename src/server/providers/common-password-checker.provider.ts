import { Inject, Injectable, Optional } from '@nestjs/common'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import type { IPasswordBreachChecker } from '../interfaces/password-breach-checker.interface'

/**
 * Base words behind the overwhelming majority of real-world weak passwords.
 *
 * Deliberately short. It is not a top-3000 dump and does not try to be: the normalisation in
 * {@link CommonPasswordChecker} strips the decorations people actually add — case, leet
 * substitutions, trailing digits and punctuation — so one entry here covers `Password1`,
 * `p@ssw0rd`, `PASSWORD123!` and the rest of a family that a raw list would have to spell out
 * one member at a time. A few hundred bases is where the published top-N lists mostly *come
 * from*; enumerating their mutations is what makes those lists long, not what makes them
 * effective.
 *
 * Entries are stored already normalised (lowercase, no decorations), because that is the form
 * they are compared in.
 */
const COMMON_BASE_WORDS: readonly string[] = [
  // The perennial top of every published list.
  'password',
  'passwort',
  'passwd',
  'senha',
  'contrasena',
  'motdepasse',
  'welcome',
  'letmein',
  'changeme',
  'secret',
  'default',
  'temporary',
  'temppassword',
  'admin',
  'administrator',
  'root',
  'toor',
  'guest',
  'test',
  'testing',
  'demo',
  'sample',
  'login',
  'user',
  'username',
  'account',
  'access',
  'private',
  'security',
  'secure',
  // Keyboard rows and walks, in the shapes people type them.
  'qwerty',
  'qwertyui',
  'qwertyuiop',
  'azerty',
  'qwertz',
  'asdfgh',
  'asdfghjk',
  'asdfghjkl',
  'zxcvbn',
  'zxcvbnm',
  'qazwsx',
  'qazwsxedc',
  'wsxedc',
  'qweasd',
  'qweasdzxc',
  'poiuytrewq',
  // Affection, the second-largest family after keyboards.
  'iloveyou',
  'ilovegod',
  'loveyou',
  'lovely',
  'sweetheart',
  'darling',
  'princess',
  'prince',
  'sunshine',
  'baby',
  'angel',
  'honey',
  'butterfly',
  'flower',
  'kisses',
  // Sport, entertainment, and the fandom perennials.
  'football',
  'baseball',
  'basketball',
  'softball',
  'soccer',
  'hockey',
  'liverpool',
  'arsenal',
  'chelsea',
  'barcelona',
  'realmadrid',
  'juventus',
  'manutd',
  'manchester',
  'superman',
  'batman',
  'spiderman',
  'starwars',
  'pokemon',
  'minecraft',
  'fortnite',
  'thomas',
  'harley',
  'ferrari',
  'porsche',
  'mercedes',
  'corvette',
  'mustang',
  // Names that top every leak, and the words that keep them company.
  'michael',
  'jennifer',
  'jessica',
  'ashley',
  'daniel',
  'charlie',
  'matthew',
  'joshua',
  'andrew',
  'robert',
  'william',
  'nicole',
  'hunter',
  'jordan',
  'taylor',
  'george',
  'maggie',
  'buster',
  'shadow',
  'ginger',
  'tigger',
  'pepper',
  'cookie',
  'peanut',
  'snoopy',
  // Words people reach for when told "make it strong".
  'dragon',
  'monkey',
  'master',
  'freedom',
  'whatever',
  'trustno',
  'nothing',
  'anything',
  'computer',
  'internet',
  'samsung',
  'google',
  'facebook',
  'apple',
  'microsoft',
  'windows',
  'letmeinnow',
  'iamgod',
  'ihateyou',
  'fuckyou',
  'fuckoff',
  'bullshit',
  'asshole',
  'summer',
  'winter',
  'spring',
  'autumn',
  'january',
  'february',
  'october',
  'november',
  'december',
  'september',
  'monday',
  'friday',
  'sunday',
  'money',
  'business',
  'company',
  'office',
  'manager',
  'director',
  'service',
  'support',
  'chocolate',
  'cheese',
  'orange',
  'purple',
  'yellow',
  'silver',
  'golden',
  'diamond',
  'phoenix',
  'thunder',
  'lightning',
  'warrior',
  'ranger',
  'killer',
  'legend',
  'forever',
  'together',
  'nevermind',
  'whatsup',
  'blessed',
  'jesus',
  'jesuschrist'
]

/**
 * Sequences a password may not consist of, in either direction.
 *
 * A run long enough to fill the minimum length is not a password no matter which characters it
 * is made of, and no word list can enumerate every window of every sequence.
 */
const SEQUENCE_ALPHABETS: readonly string[] = [
  'abcdefghijklmnopqrstuvwxyz',
  '01234567890',
  'qwertyuiopasdfghjklzxcvbnm'
]

/** Leet substitutions people use, mapped back to the letter they stand in for. */
const LEET_MAP: ReadonlyMap<string, string> = new Map([
  ['0', 'o'],
  ['1', 'i'],
  ['3', 'e'],
  ['4', 'a'],
  ['5', 's'],
  ['7', 't'],
  ['8', 'b'],
  ['9', 'g'],
  ['@', 'a'],
  ['$', 's'],
  ['!', 'i'],
  ['|', 'i'],
  ['+', 't']
])

/**
 * Reduces a password to the base word its author started from.
 *
 * Lowercases, strips the trailing digits and punctuation people append to satisfy a complexity
 * rule, maps leet substitutions back to letters, and drops what is left that is not
 * alphanumeric. `P@ssw0rd!`, `Password123`, and `password` all reduce to `password`, which is
 * why a few hundred bases stand in for a list many times longer.
 *
 * Exported for testing and for a consumer who wants to normalise their own blocklist the same
 * way before handing it to the checker.
 *
 * @param password - The raw candidate.
 * @returns The reduced base form, possibly empty.
 */
export function reduceToBaseWord(password: string): string {
  // Decoration comes off FIRST, while the digits are still digits. Mapping leet before this
  // would turn the trailing `1` of `Password1` into an `i` and leave `passwordi`, which
  // matches nothing — the order is the difference between the mechanism working and the list
  // quietly covering only its literal entries.
  const undecorated = password.toLowerCase().replace(/[\d\W_]+$/, '')

  let reduced = ''
  for (const char of undecorated) {
    const mapped = LEET_MAP.get(char) ?? char
    if (/[a-z0-9]/.test(mapped)) reduced += mapped
  }
  return reduced
}

/**
 * Whether a string is a run along one of {@link SEQUENCE_ALPHABETS}, forwards or backwards.
 */
function isSequential(value: string): boolean {
  for (const alphabet of SEQUENCE_ALPHABETS) {
    const reversed = [...alphabet].reverse().join('')
    if (alphabet.includes(value) || reversed.includes(value)) return true
  }
  return false
}

/**
 * The default password checker: refuses passwords that are common, structural, or trivially
 * decorated versions of either — offline, with no network call.
 *
 * NIST SP 800-63B §3.1.1.2 states that a verifier **SHALL** compare a prospective secret
 * against a blocklist of commonly used, expected, or compromised values, and ASVS v5 §6.2.4
 * asks for it at Level 1 — the baseline every application needs. The library used to ship
 * {@link AllowAllBreachChecker} as its default, which approved everything: a deployment on
 * defaults accepted `password1` and `12345678`, and the brute-force machinery never fired
 * because a spraying campaign that guesses one password across ten thousand accounts never
 * crosses any single account's threshold.
 *
 * **What this is and is not.** It is a floor, not a corpus. It refuses the base words behind
 * the bulk of real-world weak passwords, keyboard walks, single-character repeats, sequential
 * runs, and any decorated form of those — but it is not the full top-3000, and it knows
 * nothing about breach corpora. A deployment that wants that should either extend it through
 * `password.blocklist` or supply {@link HibpBreachChecker}, which checks a real breach corpus
 * over the network. This checker being the default is what makes the *baseline* honest; the
 * network check remains opt-in, because a library should not start talking to a third party
 * because it was upgraded.
 *
 * @layer Provider
 */
@Injectable()
export class CommonPasswordChecker implements IPasswordBreachChecker {
  /** The shipped bases plus whatever `password.blocklist` added, all pre-normalised. */
  private readonly blocked: ReadonlySet<string>

  constructor(@Inject(BYMAX_AUTH_OPTIONS) @Optional() options?: ResolvedOptions) {
    const extra = options?.password?.blocklist ?? []
    this.blocked = new Set([
      ...COMMON_BASE_WORDS,
      // The consumer's entries go through the same reduction, so they cover their own
      // decorated forms too — a deployment blocking its own product name gets `Acme2024!`
      // for free rather than having to think of it.
      ...extra.map((entry) => reduceToBaseWord(entry))
    ])
  }

  /** @inheritdoc */
  async isBreached(password: string): Promise<boolean> {
    const base = reduceToBaseWord(password)

    // Almost nothing survived the reduction, so the password was decoration wrapped around a
    // fragment: `!!!!!!!!` and `12345678` leave nothing at all, `a1234567` leaves `a`, and
    // `abc12345` leaves `abc`. Each is eight characters of padding around a word too short to
    // be one, and none of them can be caught by a list — there is no entry to write. Four is
    // the floor because below it every string is a substring of some alphabet, which would
    // make the sequence check below meaningless rather than selective.
    if (base.length < 4) return true

    if (this.blocked.has(base)) return true

    // A single character repeated, before or after reduction — `aaaaaaaa`, `AAAA1111`.
    if (/^(.)\1+$/.test(base)) return true

    // A straight run along the alphabet, the digits, or the keyboard.
    if (isSequential(base)) return true

    // The same short unit repeated to reach the length floor: `abcabcabc`, `1212121212`.
    // Bounded to units of 1–4 so this stays a check on padding, not on any repetition.
    if (/^(.{1,4}?)\1{2,}$/.test(base)) return true

    return false
  }
}
