/**
 * @fileoverview The strength bar every module secret must clear: long enough and varied enough that
 * it was generated, not typed.
 *
 * @layer Config
 */

/**
 * Computes the Shannon entropy of a string in bits per character.
 *
 * Used as a first-order filter to detect `jwt.secret` values with extremely
 * low character-frequency diversity (e.g. all-same character, simple 2-char
 * alternation). It does NOT detect sequential or enumerable patterns — a secret
 * composed of all unique characters arranged alphabetically passes this check.
 * The entropy gate is a necessary but not sufficient signal for randomness;
 * the primary protection is that secrets should be generated with
 * `crypto.randomBytes(32).toString('base64')`.
 */
function shannonEntropy(value: string): number {
  const freq = new Map<string, number>()
  for (const ch of value) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1)
  }
  return [...freq.values()].reduce((sum, count) => {
    const p = count / value.length
    return sum - p * Math.log2(p)
  }, 0)
}

/**
 * The shortest a secret may be, in characters, for every secret option: `jwt.secret`, each retired
 * signing secret, `identifierKey` and `apiKeys.pepper`. A host's own configuration check reads it
 * here instead of keeping a copy that could drift from the one startup enforces.
 */
export const AUTH_SECRET_MIN_LENGTH = 32

/**
 * Requires a secret to be present, at least {@link AUTH_SECRET_MIN_LENGTH} characters and at least
 * 3.5 bits per character of Shannon entropy.
 *
 * @param secret - The configured value; a runtime-nullish value is refused with the same message
 *   as an empty one.
 * @param name - The option name, for the error message.
 * @throws {Error} Naming the option and the check it failed.
 */
export function validateSecretStrength(secret: string, name: string): void {
  // Guard against runtime-nullish values (e.g. ConfigService returning undefined for an
  // unset environment variable). The interface declares `secret: string` but callers
  // frequently use `config.get('JWT_SECRET')` which returns `string | undefined`.
  // Without this check the subsequent `.length` access would throw a raw TypeError
  // instead of the descriptive [BymaxAuthModule] startup error.
  if (!secret) {
    throw new Error(
      `[BymaxAuthModule] ${name} is required and must not be empty. ` +
        `Generate a secure secret with: node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`
    )
  }
  if (secret.length < AUTH_SECRET_MIN_LENGTH) {
    throw new Error(
      `[BymaxAuthModule] ${name} must be at least ${AUTH_SECRET_MIN_LENGTH} characters long. ` +
        `Generate a secure secret with: node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`
    )
  }

  const entropy = shannonEntropy(secret)
  if (entropy < 3.5) {
    throw new Error(
      `[BymaxAuthModule] ${name} has insufficient entropy (${entropy.toFixed(2)} bits/char, ` +
        `minimum: 3.5 bits/char). The secret appears to contain repetitive or predictable patterns. ` +
        `Generate a secure secret with: node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`
    )
  }
}
