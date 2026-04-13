# Node.js Crypto Guidelines — @bymax-one/nest-auth

> **Audience:** AI agents and developers working on this codebase.
> **Stack:** Node.js 24+ `node:crypto`, zero external crypto dependencies
> **Rule:** Follow these guidelines for all cryptographic operations in this project.

---

## Table of Contents

1. [Core Principle: node:crypto Only](#1-core-principle-nodecrypto-only)
2. [Password Hashing with scrypt](#2-password-hashing-with-scrypt)
3. [AES-256-GCM Encryption](#3-aes-256-gcm-encryption)
4. [TOTP/HOTP Implementation](#4-totphotp-implementation)
5. [Secure Token Generation](#5-secure-token-generation)
6. [SHA-256 Hashing](#6-sha-256-hashing)
7. [Timing-Safe Comparison](#7-timing-safe-comparison)
8. [Random Number Generation](#8-random-number-generation)
9. [Key Management](#9-key-management)
10. [Anti-Patterns](#10-anti-patterns)
11. [Quick Reference Checklist](#quick-reference-checklist)

---

## 1. Core Principle: node:crypto Only

### The Rule

Every cryptographic operation in `@bymax-one/nest-auth` MUST use `node:crypto` exclusively. The package has **zero runtime dependencies** (`"dependencies": {}`). This is a deliberate architectural decision, not a temporary shortcut.

### Why Zero External Crypto Dependencies

**Supply chain security.** Every npm package you add to a cryptographic path is an attack surface. Native `node:crypto` ships with the Node.js binary itself, is maintained by the Node.js Security Team, undergoes continuous OpenSSL audits, and cannot be tampered with via npm registry compromises.

**No native binary compilation.** Packages like `bcrypt` and `argon2` require C++ bindings compiled via `node-gyp`. This creates friction across platforms, CI environments, Docker images, and serverless runtimes. `node:crypto` works everywhere Node.js runs, with zero build tooling.

**No silent truncation.** Unlike `bcrypt`, which silently truncates passwords longer than 72 bytes, `scrypt` processes the full password regardless of length.

### Explicitly Banned Packages

Do NOT install, import, or suggest any of the following:

| Package | Why Banned | Use Instead |
|---------|-----------|-------------|
| `bcrypt` / `bcryptjs` | C++ bindings or pure-JS slowness; truncates at 72 bytes | `crypto.scrypt` |
| `argon2` | C++ bindings; not available natively in Node.js | `crypto.scrypt` |
| `otpauth` / `speakeasy` / `otplib` | Unnecessary dependency for TOTP | `crypto.createHmac('sha1', ...)` |
| `uuid` | Only used for random tokens | `crypto.randomBytes` / `crypto.randomUUID` |
| `nanoid` | Only used for random tokens | `crypto.randomBytes` |
| `crypto-js` | Browser-oriented; slower; insecure defaults | `node:crypto` |
| `tweetnacl` | Not needed when `node:crypto` covers all use cases | `node:crypto` |
| `node-forge` | Redundant with `node:crypto` | `node:crypto` |
| `scrypt-js` | Pure-JS scrypt; unnecessary when native exists | `crypto.scrypt` |

### Import Convention

Always import from the `node:` prefixed module:

```typescript
// CORRECT — explicit built-in reference
import { scrypt, randomBytes, createCipheriv, createHmac, timingSafeEqual, createHash, randomInt } from 'node:crypto';
import { promisify } from 'node:util';

// WRONG — ambiguous, could collide with npm package named "crypto"
import { scrypt } from 'crypto';
```

The `node:` prefix was introduced in Node.js 16 and is mandatory in this project. It explicitly signals that the import resolves to a built-in module, preventing any npm package from shadowing it.

---

## 2. Password Hashing with scrypt

### Overview

`scrypt` is a memory-hard password-based key derivation function designed to resist brute-force attacks by requiring significant memory and CPU resources. OWASP 2024+ recommends Argon2id > scrypt > bcrypt for new systems. Since scrypt is natively available in `node:crypto`, it eliminates external dependencies while providing strong security guarantees.

### Parameters (Project Defaults)

| Parameter | Config Key | Default Value | Description |
|-----------|-----------|---------------|-------------|
| N (cost factor) | `password.costFactor` | 2^15 (32768) | CPU/memory cost. Doubling N doubles time and memory. |
| r (block size) | `password.blockSize` | 8 | Block size. Each block is 128*r bytes. |
| p (parallelization) | `password.parallelization` | 1 | Parallelization factor. |
| keyLen | (fixed) | 64 | Derived key length in bytes (512 bits). |
| salt | (generated) | 16 bytes | Unique random salt per password via `crypto.randomBytes(16)`. |

**Memory usage formula:** `128 * N * r * p` bytes = `128 * 32768 * 8 * 1` = **32 MB** per hash operation.

### Storage Format

```
scrypt:{salt_hex}:{derived_hex}
```

- Prefix `scrypt:` enables future algorithm migration (e.g., if switching to Argon2 when natively available)
- Salt is stored as lowercase hexadecimal (32 characters for 16 bytes)
- Derived key is stored as lowercase hexadecimal (128 characters for 64 bytes)

Example: `scrypt:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4:7f8e9d...` (total ~164 characters)

### Reference Implementation

```typescript
import { scrypt, randomBytes, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);

/**
 * Hashes a plaintext password using scrypt.
 * Generates a unique 16-byte salt per password.
 *
 * @param plainPassword - The user's plaintext password
 * @returns Hash string in format scrypt:{salt_hex}:{derived_hex}
 */
async function hashPassword(plainPassword: string): Promise<string> {
  const salt = randomBytes(16);
  const derived = (await scryptAsync(plainPassword, salt, 64, {
    N: 32768,  // 2^15 — configurable via password.costFactor
    r: 8,      // configurable via password.blockSize
    p: 1,      // configurable via password.parallelization
  })) as Buffer;
  return `scrypt:${salt.toString('hex')}:${derived.toString('hex')}`;
}

/**
 * Compares a plaintext password against a stored scrypt hash.
 * Uses timing-safe comparison to prevent timing attacks.
 *
 * @param plainPassword - The user's plaintext password
 * @param storedHash - The stored hash in scrypt:{salt}:{hash} format
 * @returns true if the password matches
 */
async function comparePassword(plainPassword: string, storedHash: string): Promise<boolean> {
  const [prefix, saltHex, hashHex] = storedHash.split(':');
  if (prefix !== 'scrypt' || !saltHex || !hashHex) return false;

  const salt = Buffer.from(saltHex, 'hex');
  const stored = Buffer.from(hashHex, 'hex');
  const derived = (await scryptAsync(plainPassword, salt, 64, {
    N: 32768,
    r: 8,
    p: 1,
  })) as Buffer;

  // CRITICAL: Always use timingSafeEqual — never use === or Buffer.equals()
  return timingSafeEqual(stored, derived);
}
```

### Key Rules

1. **Always generate a fresh salt** for every `hash()` call. Never reuse salts across passwords.
2. **Always use `promisify(scrypt)`** for the async version. The callback form works but `async/await` integrates better with NestJS services.
3. **Always compare with `timingSafeEqual`** — never use `===`, `Buffer.equals()`, or string comparison.
4. **Always parse the stored format** by splitting on `:` and validating the `scrypt` prefix before comparison.
5. **Never lower N below 2^14 (16384)** in production. The default 2^15 provides adequate security margins as of 2024-2026.
6. **Recovery codes** are also hashed with scrypt using the same parameters — they are treated as passwords.

### Parameter Tuning Guidelines

| Environment | N | r | p | Time per hash (~) | Memory |
|-------------|---|---|---|-------------------|--------|
| Production (default) | 2^15 (32768) | 8 | 1 | ~80-120ms | 32 MB |
| Testing / CI | 2^14 (16384) | 8 | 1 | ~40-60ms | 16 MB |
| High-security | 2^16 (65536) | 8 | 1 | ~160-240ms | 64 MB |
| **Never use** | < 2^14 | < 8 | — | — | — |

---

## 3. AES-256-GCM Encryption

### Overview

AES-256-GCM (Galois/Counter Mode) provides authenticated encryption — both confidentiality and integrity in a single operation. It is used in this project to encrypt TOTP secrets at rest. GCM produces an authentication tag that detects tampering; if the ciphertext or associated data is modified, decryption will fail.

### Parameters (Fixed)

| Parameter | Value | Notes |
|-----------|-------|-------|
| Algorithm | `aes-256-gcm` | 256-bit key, authenticated encryption |
| Key | 32 bytes (256 bits) | Derived from base64-encoded `mfa.encryptionKey` config |
| IV (nonce) | 12 bytes (96 bits) | Generated fresh via `crypto.randomBytes(12)` per encryption |
| Auth tag length | 16 bytes (128 bits) | Default GCM tag length — do not reduce |

### Output Format

```
base64(iv):base64(authTag):base64(ciphertext)
```

Three colon-separated base64 strings. Example:
```
dGhpcyBpcyBhbiBpdg==:YXV0aFRhZ0V4YW1wbGU=:Y2lwaGVydGV4dA==
```

### Reference Implementation

```typescript
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;   // 96 bits — optimal for GCM
const TAG_LENGTH = 16;  // 128-bit auth tag

/**
 * Encrypts a TOTP secret using AES-256-GCM.
 * Generates a fresh 12-byte IV for each call — NEVER reuse IVs with the same key.
 *
 * @param plaintext - The TOTP secret to encrypt
 * @param key - 32-byte encryption key (Buffer)
 * @returns Encrypted string in format base64(iv):base64(tag):base64(ciphertext)
 */
function encryptSecret(plaintext: string, key: Buffer): string {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });

  let encrypted = cipher.update(plaintext, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);

  const authTag = cipher.getAuthTag();

  return [
    iv.toString('base64'),
    authTag.toString('base64'),
    encrypted.toString('base64'),
  ].join(':');
}

/**
 * Decrypts a TOTP secret encrypted with encryptSecret().
 *
 * @param encryptedString - String in format base64(iv):base64(tag):base64(ciphertext)
 * @param key - 32-byte encryption key (Buffer)
 * @returns Decrypted plaintext string
 * @throws Error if authentication fails (tampered data)
 */
function decryptSecret(encryptedString: string, key: Buffer): string {
  const [ivB64, tagB64, ctB64] = encryptedString.split(':');

  const iv = Buffer.from(ivB64, 'base64');
  const authTag = Buffer.from(tagB64, 'base64');
  const ciphertext = Buffer.from(ctB64, 'base64');

  const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(ciphertext);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return decrypted.toString('utf8');
}
```

### Key Rules

1. **NEVER reuse an IV with the same key.** GCM security completely breaks down if (key, IV) pairs repeat. Always call `randomBytes(12)` for each encryption operation.
2. **Always use 12-byte IVs for GCM.** While GCM supports other IV lengths, 12 bytes (96 bits) is the NIST-recommended size and the most efficient — other lengths require an additional GHASH computation.
3. **Always verify the auth tag on decryption.** `decipher.setAuthTag(authTag)` MUST be called before `decipher.update()` or `decipher.final()`. If the tag is invalid or missing, `final()` will throw.
4. **Never suppress decryption errors.** If `decipher.final()` throws, the ciphertext or tag has been tampered with. Do not catch and return a fallback — propagate the error.
5. **Use Buffer operations, not string encoding, for intermediate values.** Only convert to base64 for the final storage format.
6. **The encryption key MUST be exactly 32 bytes.** Validate at module initialization (see [Section 9: Key Management](#9-key-management)).

### GCM vs Other Modes

| Mode | Authenticated? | IV Reuse Tolerance | Use Case |
|------|---------------|-------------------|----------|
| **GCM** (this project) | Yes | None (catastrophic) | Encrypt-then-authenticate in one step |
| CBC + HMAC | Separate HMAC needed | More tolerant but still bad | Legacy systems |
| CTR | No | None | Stream encryption (needs separate MAC) |
| ECB | No | N/A (no IV) | **NEVER USE** — leaks patterns |

---

## 4. TOTP/HOTP Implementation

### Overview

This project implements TOTP (Time-based One-Time Password, RFC 6238) and HOTP (HMAC-based One-Time Password, RFC 4226) natively using `node:crypto` HMAC-SHA1. No external packages like `otpauth`, `speakeasy`, or `otplib` are used.

### RFC Compliance

- **RFC 4226 (HOTP):** HMAC-SHA1 based, counter-driven. The foundation for TOTP.
- **RFC 6238 (TOTP):** Time-based extension of HOTP. Uses `floor(unix_time / period)` as the counter.
- **Algorithm:** HMAC-SHA1 is mandated by RFC 4226 and universally supported by authenticator apps (Google Authenticator, Authy, 1Password, etc.).

### Why HMAC-SHA1 (Not SHA-256)

Although SHA-1 has known collision weaknesses, HMAC-SHA1 remains secure. HMAC's security depends on the PRF (pseudorandom function) property of the hash, not its collision resistance. RFC 4226 Section 5.3 specifies SHA-1, and virtually all authenticator apps implement only SHA-1. Using SHA-256 would break compatibility.

### Base32 Decoding

TOTP secrets are encoded in Base32 (RFC 4648) for compatibility with the `otpauth://` URI scheme. This project includes a custom decoder:

```typescript
/**
 * Decodes a Base32-encoded string (RFC 4648) to a Buffer.
 * Used to convert TOTP secrets from their display/URI format to raw bytes for HMAC.
 *
 * @param encoded - Base32 string (A-Z, 2-7, optional = padding)
 * @returns Buffer of decoded bytes
 * @throws Error on invalid Base32 characters
 */
function base32Decode(encoded: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const stripped = encoded.replace(/=+$/, '').toUpperCase();
  let bits = '';
  for (const char of stripped) {
    const val = alphabet.indexOf(char);
    if (val === -1) throw new Error(`Invalid base32 character: ${char}`);
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  return Buffer.from(bytes);
}
```

### HOTP Generation (RFC 4226)

```typescript
import { createHmac } from 'node:crypto';

/**
 * Generates an HOTP code per RFC 4226.
 *
 * Steps:
 * 1. Convert counter to 8-byte big-endian buffer
 * 2. Compute HMAC-SHA1(secret, counter_buffer)
 * 3. Dynamic truncation: extract 4 bytes at offset determined by last nibble
 * 4. Mask to 31 bits, modulo 10^digits, pad with leading zeros
 *
 * @param secret - Raw secret bytes (decoded from Base32)
 * @param counter - 8-byte counter value
 * @param digits - Number of digits in the OTP (default: 6)
 * @returns OTP string, zero-padded to `digits` length
 */
function generateHOTP(secret: Buffer, counter: number, digits = 6): string {
  // Step 1: Counter as 8-byte big-endian
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));

  // Step 2: HMAC-SHA1
  const hmac = createHmac('sha1', secret).update(buf).digest();

  // Step 3: Dynamic truncation (RFC 4226 Section 5.3)
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % (10 ** digits);

  // Step 4: Zero-pad
  return code.toString().padStart(digits, '0');
}
```

### TOTP Generation (RFC 6238)

```typescript
/**
 * Generates a TOTP code for the current time.
 *
 * @param secret - Raw secret bytes (decoded from Base32)
 * @param period - Time step in seconds (default: 30)
 * @param digits - Number of digits (default: 6)
 * @returns Current TOTP code
 */
function generateTOTP(secret: Buffer, period = 30, digits = 6): string {
  const counter = Math.floor(Date.now() / 1000 / period);
  return generateHOTP(secret, counter, digits);
}
```

### TOTP Verification with Window

```typescript
/**
 * Verifies a TOTP code with a tolerance window.
 * Checks current period plus/minus `window` periods.
 *
 * A window of 1 means checking 3 time slots: previous, current, next.
 * This accounts for clock drift between server and authenticator app.
 *
 * @param secret - Raw secret bytes
 * @param code - User-provided TOTP code
 * @param window - Number of periods to check before/after current (default: 1)
 * @param period - Time step in seconds (default: 30)
 * @param digits - Number of digits (default: 6)
 * @returns true if the code matches any slot in the window
 */
function verifyTOTP(
  secret: Buffer,
  code: string,
  window = 1,
  period = 30,
  digits = 6,
): boolean {
  const counter = Math.floor(Date.now() / 1000 / period);
  for (let i = -window; i <= window; i++) {
    if (generateHOTP(secret, counter + i, digits) === code) return true;
  }
  return false;
}
```

### TOTP URI (QR Code Generation)

```typescript
/**
 * Builds an otpauth:// URI for QR code generation.
 * Compatible with Google Authenticator, Authy, 1Password, etc.
 *
 * Format: otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30
 *
 * @param secret - Base32-encoded secret (NOT raw bytes)
 * @param account - User identifier (email)
 * @param issuer - Service name (from mfa.issuer config)
 */
function buildTotpUri(secret: string, account: string, issuer: string): string {
  const encodedIssuer = encodeURIComponent(issuer);
  const encodedAccount = encodeURIComponent(account);
  return `otpauth://totp/${encodedIssuer}:${encodedAccount}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;
}
```

### TOTP Secret Generation

```typescript
import { randomBytes } from 'node:crypto';

/**
 * Generates a cryptographically secure TOTP secret.
 * Returns 20 random bytes (160 bits), which is the standard HMAC-SHA1 key size.
 * The secret is then Base32-encoded for storage and QR code URI generation.
 */
function generateTotpSecret(): Buffer {
  return randomBytes(20);  // 160 bits = SHA-1 output size
}
```

### Key Rules

1. **HMAC-SHA1 only.** Do not switch to SHA-256 for TOTP — authenticator apps will not work.
2. **Window of 1** is the default tolerance. This checks 3 time slots (previous, current, next = 90 seconds total). Do not increase beyond 2 unless there is a documented reason.
3. **TOTP secrets are encrypted at rest** with AES-256-GCM (Section 3). They are never stored in plaintext in the database.
4. **Replay prevention:** After successful TOTP verification, store the used code in Redis with a TTL of `3 * period` (90 seconds) to prevent replay attacks. Check Redis before verifying.
5. **Use `BigInt` for the counter buffer** — `buf.writeBigUInt64BE(BigInt(counter))` ensures correct 8-byte encoding for large counter values.

---

## 5. Secure Token Generation

### Overview

Secure random tokens are used for refresh tokens, password reset tokens, email verification tokens, and session identifiers. All token generation MUST use `crypto.randomBytes` — never `Math.random()`, `Date.now()`, UUIDs from `uuid` package, or any other non-cryptographic source.

### Token Generation Patterns

```typescript
import { randomBytes, randomUUID } from 'node:crypto';

/**
 * Generates a cryptographically secure random token as a hex string.
 *
 * @param bytes - Number of random bytes (default: 32 = 256 bits = 64 hex chars)
 * @returns Hex-encoded token string
 */
function generateToken(bytes = 32): string {
  return randomBytes(bytes).toString('hex');
}

/**
 * Generates a URL-safe random token using base64url encoding.
 * Useful for tokens that appear in URLs (password reset links, email verification).
 *
 * @param bytes - Number of random bytes (default: 32)
 * @returns Base64url-encoded token string (no padding)
 */
function generateUrlSafeToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}
```

### Token Length Recommendations

| Use Case | Bytes | Encoding | Output Length | Entropy |
|----------|-------|----------|---------------|---------|
| Refresh token | 32 | hex | 64 chars | 256 bits |
| Password reset token | 32 | hex | 64 chars | 256 bits |
| Email verification token | 32 | hex | 64 chars | 256 bits |
| CSRF token | 32 | hex | 64 chars | 256 bits |
| Session ID | 32 | hex | 64 chars | 256 bits |
| Recovery code | 16 | hex | 32 chars | 128 bits |

**Minimum: 16 bytes (128 bits) for any security token.** The project default is 32 bytes (256 bits).

### UUID Generation

For refresh tokens stored in Redis, this project uses `crypto.randomUUID()` (v4 UUID):

```typescript
import { randomUUID } from 'node:crypto';

// Native cryptographic UUID — no 'uuid' package needed
const refreshTokenId = randomUUID();
// Example: '550e8400-e29b-41d4-a716-446655440000'
```

`crypto.randomUUID()` is available since Node.js 19+ and uses the same CSPRNG as `randomBytes`.

### Key Rules

1. **Never use `Math.random()` for any token, code, or secret.** `Math.random()` is not cryptographically secure — its output is predictable and can be reverse-engineered.
2. **Never use `Date.now()` as a token or seed.** Timestamps are fully predictable.
3. **Always use `randomBytes`** for token generation. It reads from the OS cryptographic random source (`/dev/urandom` on Linux/macOS, `BCryptGenRandom` on Windows).
4. **Store tokens hashed when possible.** Refresh tokens and password reset tokens should be stored as SHA-256 hashes in the database (see [Section 6](#6-sha-256-hashing)), with only the plaintext returned to the user once.

---

## 6. SHA-256 Hashing

### Overview

SHA-256 is used for **non-password hashing** — specifically for hashing tokens before storage and for generating deterministic identifiers. SHA-256 is a fast, non-reversible hash function. It is NOT suitable for password hashing (use scrypt for that — see Section 2).

### Use Cases in This Project

| Use Case | Input | Why SHA-256 |
|----------|-------|-------------|
| Refresh token storage | Random token (high entropy) | Fast lookup; token already has 256 bits of entropy |
| Password reset token storage | Random token | Same as above |
| OTP identifier | `tenantId:email` | Deterministic, non-reversible identifier for Redis keys |
| Token blacklisting | JWT `jti` | Fast comparison for blacklisted tokens |

### Reference Implementation

```typescript
import { createHash } from 'node:crypto';

/**
 * Computes SHA-256 hash of the input string.
 * Used for hashing high-entropy tokens before storage.
 *
 * DO NOT use this for password hashing — use scrypt instead.
 *
 * @param input - String to hash
 * @returns Hex-encoded SHA-256 digest (64 characters)
 */
function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}
```

### Token Storage Pattern

```typescript
// When issuing a refresh token:
const rawToken = randomBytes(32).toString('hex');     // Give this to the user
const hashedToken = sha256(rawToken);                  // Store this in Redis/DB

// When verifying a refresh token:
const incomingHash = sha256(incomingRawToken);
// Look up incomingHash in storage
```

### Why Hash Tokens Before Storage

If the database or Redis is compromised, an attacker who obtains hashed tokens cannot reconstruct the originals (SHA-256 is preimage-resistant). This limits the blast radius of a data breach — stolen hashes cannot be used to impersonate users.

### Key Rules

1. **Never use SHA-256 for password hashing.** SHA-256 is fast by design — a GPU can compute billions of SHA-256 hashes per second. Passwords must use scrypt.
2. **SHA-256 is appropriate for high-entropy inputs** (random tokens, UUIDs) because the input space is too large to brute-force.
3. **Always use hex encoding** for stored hashes in this project. This ensures consistent comparison and avoids encoding ambiguity.
4. **The `createHash` object is single-use.** After calling `.digest()`, the hash object cannot be reused. Create a new one for each hash operation.

### OTP Identifier Hashing

For OTP storage keys in Redis, tenant-scoped identifiers are hashed to avoid storing raw emails:

```typescript
/**
 * Creates a deterministic, tenant-scoped identifier for OTP Redis keys.
 * Hashes the combination to avoid storing raw email in Redis key names.
 */
function otpIdentifier(tenantId: string, email: string): string {
  return sha256(`${tenantId}:${email}`);
}

// Redis key: auth:otp:password_reset:{sha256(tenantId:email)}
```

---

## 7. Timing-Safe Comparison

### Overview

`crypto.timingSafeEqual` performs constant-time comparison of two buffers. This prevents **timing attacks**, where an attacker measures how long a comparison takes to determine how many bytes match. Regular string comparison (`===`) and `Buffer.equals()` short-circuit on the first mismatched byte, leaking information through execution time.

### When to Use

Use `timingSafeEqual` for **every security-sensitive comparison** in this project:

| Comparison | Why Timing-Safe |
|-----------|----------------|
| scrypt derived key vs stored hash | Prevents password guessing via timing |
| TOTP code vs generated code | Prevents OTP guessing via timing |
| OTP code vs stored code | Same as above |
| Recovery code hash comparison | Same as above |
| Token comparison (when not hashed) | Prevents token guessing via timing |

### Reference Implementation

```typescript
import { timingSafeEqual } from 'node:crypto';

/**
 * Performs constant-time comparison of two strings.
 * Both strings are converted to Buffers for timingSafeEqual.
 *
 * CRITICAL: Both buffers MUST be the same length. If lengths differ,
 * timingSafeEqual throws. Handle length mismatch BEFORE calling.
 *
 * @param a - First string
 * @param b - Second string
 * @returns true if strings are identical
 */
function safeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  // Length check must happen BEFORE timingSafeEqual.
  // This leaks length information, but length is not secret for
  // fixed-format values (OTPs are always 6 digits, hashes are fixed length).
  if (bufA.length !== bufB.length) return false;

  return timingSafeEqual(bufA, bufB);
}
```

### Buffer Length Requirement

`timingSafeEqual` throws a `TypeError` if the two buffers have different lengths. This is by design — comparing buffers of different lengths in constant time is not meaningful. Handle this case explicitly:

```typescript
// CORRECT — check length first
if (bufA.length !== bufB.length) return false;
return timingSafeEqual(bufA, bufB);

// WRONG — will throw TypeError
return timingSafeEqual(Buffer.from('short'), Buffer.from('much longer string'));
```

### Practical Constant-Time Patterns

#### Pattern 1: Comparing scrypt outputs (always same length)

```typescript
// Both derived keys are always 64 bytes — no length check needed
// (but it does not hurt to include one defensively)
const stored = Buffer.from(hashHex, 'hex');   // 64 bytes
const derived = await scryptAsync(pw, salt, 64, opts) as Buffer;  // 64 bytes
return timingSafeEqual(stored, derived);
```

#### Pattern 2: Comparing TOTP codes (fixed digit length)

```typescript
// TOTP codes are always 6 digits — pad both sides
const expected = generateHOTP(secret, counter, 6);  // "048291"
const provided = code.padStart(6, '0');              // Ensure same length
return safeCompare(expected, provided);
```

#### Pattern 3: Comparing hashed tokens (always same length)

```typescript
// SHA-256 hex output is always 64 chars
const storedHash = sha256(storedRawToken);
const incomingHash = sha256(incomingRawToken);
return safeCompare(storedHash, incomingHash);
```

### Key Rules

1. **Never use `===` for comparing secrets, tokens, hashes, or OTP codes.** String equality is not constant-time.
2. **Never use `Buffer.equals()`** for security comparisons. Although it compares buffers, it is not guaranteed to be constant-time.
3. **Always ensure equal buffer lengths** before calling `timingSafeEqual`. Different lengths will throw.
4. **For scrypt comparison, lengths are inherently equal** (both are 64-byte derived keys). For string comparisons (OTP codes), normalize lengths first.
5. **Leaking length information is acceptable** for fixed-format values (OTPs, hex hashes). The security goal is to prevent byte-by-byte timing leaks.

---

## 8. Random Number Generation

### Overview

For generating numeric OTP codes (password reset, email verification), this project uses `crypto.randomInt()` — a cryptographically secure random integer generator built into Node.js. It provides uniform distribution over the specified range using rejection sampling internally.

### OTP Generation

```typescript
import { randomInt } from 'node:crypto';

/**
 * Generates a cryptographically secure numeric OTP.
 *
 * Uses crypto.randomInt() which provides uniform distribution
 * via rejection sampling — no modulo bias.
 *
 * @param length - Number of digits (default: 6, max recommended: 8)
 * @returns Zero-padded numeric string (e.g., "048291")
 */
function generateOTP(length = 6): string {
  // IMPORTANT: length must be <= 8 to stay within MAX_SAFE_INTEGER.
  // 10^9 = 1,000,000,000 which exceeds randomInt's max of 2^48.
  // Actually: randomInt max is < 2^48, and 10^8 = 100,000,000 is safe.
  // 10^15 < 2^48 ≈ 2.8 * 10^14... so 10^8 is well within range.
  if (length < 1 || length > 8) {
    throw new Error('OTP length must be between 1 and 8');
  }

  const max = 10 ** length;  // e.g., 10^6 = 1,000,000
  const code = randomInt(0, max);  // [0, 1000000)
  return code.toString().padStart(length, '0');
}
```

### crypto.randomInt Constraints

- **Range:** `randomInt(min, max)` generates integers in `[min, max)` (min inclusive, max exclusive).
- **Maximum range:** `max - min` must be less than `2^48`. This means OTP lengths up to 14 digits are technically safe, but this project caps at 8 for practical reasons.
- **Synchronous or async:** Both `randomInt(max)` (sync) and `randomInt(max, callback)` (async) are available. This project uses the synchronous form for OTPs since the operation is instantaneous.

### Why Not Math.random()

```typescript
// WRONG — Math.random() is NOT cryptographically secure
// It uses a PRNG seeded from a low-entropy source. Output is predictable.
const insecureOTP = Math.floor(Math.random() * 1000000).toString().padStart(6, '0');

// CORRECT — crypto.randomInt() uses the OS CSPRNG
const secureOTP = randomInt(0, 1000000).toString().padStart(6, '0');
```

`Math.random()` uses V8's xorshift128+ PRNG. An attacker who observes a few outputs can predict all future values. For security-critical applications, this is a complete compromise.

### Key Rules

1. **Always use `crypto.randomInt`** for numeric codes. Never `Math.random()` or `Math.floor(Math.random() * ...)`.
2. **OTP length must be <= 8.** This is enforced to ensure `10^length` is well within `randomInt`'s safe range.
3. **Always zero-pad** the result with `.padStart(length, '0')`. A raw number like `48291` must become `"048291"` for a 6-digit OTP.
4. **Validate OTP length** at the service boundary. Reject lengths outside `[1, 8]`.

---

## 9. Key Management

### Encryption Key Validation

The MFA encryption key (`mfa.encryptionKey`) must be exactly 32 bytes (256 bits) when decoded from base64. This is validated at module startup.

```typescript
/**
 * Validates and decodes the AES-256-GCM encryption key from configuration.
 * The key is stored as a base64 string and must decode to exactly 32 bytes.
 *
 * @param base64Key - Base64-encoded encryption key from config
 * @returns 32-byte Buffer ready for use with createCipheriv
 * @throws Error if key is not exactly 32 bytes after decoding
 */
function validateEncryptionKey(base64Key: string): Buffer {
  const keyBuffer = Buffer.from(base64Key, 'base64');
  if (keyBuffer.length !== 32) {
    throw new Error(
      `MFA encryption key must be exactly 32 bytes (256 bits). ` +
      `Got ${keyBuffer.length} bytes. ` +
      `Generate with: node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`
    );
  }
  return keyBuffer;
}
```

### Generating a Proper Encryption Key

```bash
# Generate a 32-byte (256-bit) key encoded as base64 (44 characters)
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"
```

This produces a 44-character base64 string (e.g., `K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=`) that decodes back to exactly 32 bytes.

### JWT Secret Validation

JWT secrets undergo entropy validation at startup to reject weak secrets:

```typescript
/**
 * Calculates Shannon entropy of a string in bits per character.
 * Used to validate JWT secrets and encryption keys at startup.
 *
 * Minimum required: 3.5 bits/char (rejects low-entropy strings).
 * Recommended: >= 5.0 bits/char.
 * crypto.randomBytes(32).toString('base64') produces ~5.9 bits/char.
 *
 * @param str - The string to analyze
 * @returns Entropy in bits per character
 */
function shannonEntropy(str: string): number {
  const freq = new Map<string, number>();
  for (const char of str) {
    freq.set(char, (freq.get(char) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
```

### JWT Secret Validation Rules

| Check | Threshold | Rationale |
|-------|-----------|-----------|
| Minimum length | 32 characters | Ensures sufficient key material |
| Minimum Shannon entropy | 3.5 bits/char | Rejects `aaaa...`, `abcabc...`, and dictionary words |
| All-same-character check | Reject | `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` has 0 entropy |
| Recommended generation | `crypto.randomBytes(32).toString('base64')` | 44 chars, ~5.9 bits/char |

### Startup Validation Pattern

```typescript
// At module initialization (NestJS onModuleInit or factory function)
function validateSecrets(config: AuthModuleOptions): void {
  // 1. JWT secret
  const jwtSecret = config.jwt.secret;
  if (jwtSecret.length < 32) {
    throw new Error('JWT secret must be at least 32 characters');
  }
  const entropy = shannonEntropy(jwtSecret);
  if (entropy < 3.5) {
    throw new Error(
      `JWT secret has insufficient entropy: ${entropy.toFixed(2)} bits/char (minimum: 3.5). ` +
      `Generate with: node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`
    );
  }

  // 2. MFA encryption key (if MFA enabled)
  if (config.mfa?.enabled) {
    validateEncryptionKey(config.mfa.encryptionKey);
  }
}
```

### Key Storage Best Practices

1. **Never commit keys to source control.** Use environment variables (`process.env.JWT_SECRET`, `process.env.MFA_ENCRYPTION_KEY`).
2. **Use `.env` files for local development only.** Add `.env` to `.gitignore`.
3. **Use secrets managers in production.** AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, or HashiCorp Vault.
4. **Rotate keys periodically.** Support key rotation by accepting an array of decryption keys (current + previous) while only encrypting with the current key.
5. **Log validation results at startup** (success/failure, NOT the key values). This helps diagnose configuration errors in production.

---

## 10. Anti-Patterns

This section documents common mistakes and their corrections. AI agents and developers must recognize and avoid these patterns.

### Anti-Pattern 1: Using bcrypt Instead of scrypt

```typescript
// WRONG — external dependency with C++ bindings
import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(password, 12);
const match = await bcrypt.compare(password, hash);

// CORRECT — native scrypt, zero dependencies
import { scrypt, randomBytes, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
const scryptAsync = promisify(scrypt);

const salt = randomBytes(16);
const derived = await scryptAsync(password, salt, 64, { N: 32768, r: 8, p: 1 }) as Buffer;
const hash = `scrypt:${salt.toString('hex')}:${derived.toString('hex')}`;
```

### Anti-Pattern 2: Using Math.random() for Tokens or OTPs

```typescript
// WRONG — predictable, not cryptographically secure
const token = Math.random().toString(36).substring(2);
const otp = Math.floor(Math.random() * 1000000).toString().padStart(6, '0');

// CORRECT — cryptographically secure
import { randomBytes, randomInt } from 'node:crypto';
const token = randomBytes(32).toString('hex');
const otp = randomInt(0, 1000000).toString().padStart(6, '0');
```

### Anti-Pattern 3: String Comparison for Secrets

```typescript
// WRONG — timing attack vulnerability
if (userToken === storedToken) { /* grant access */ }
if (derivedHash.toString('hex') === storedHash) { /* match */ }
if (Buffer.from(a).equals(Buffer.from(b))) { /* not constant-time */ }

// CORRECT — constant-time comparison
import { timingSafeEqual } from 'node:crypto';
const bufA = Buffer.from(userToken, 'hex');
const bufB = Buffer.from(storedToken, 'hex');
if (bufA.length === bufB.length && timingSafeEqual(bufA, bufB)) { /* grant access */ }
```

### Anti-Pattern 4: Reusing IV/Nonce in AES-GCM

```typescript
// WRONG — static or reused IV completely breaks GCM security
const STATIC_IV = Buffer.from('000000000000', 'hex');
const cipher = createCipheriv('aes-256-gcm', key, STATIC_IV);

// WRONG — deriving IV from plaintext
const iv = createHash('md5').update(plaintext).digest().subarray(0, 12);

// CORRECT — fresh random IV every time
import { randomBytes, createCipheriv } from 'node:crypto';
const iv = randomBytes(12);  // 12 bytes for GCM
const cipher = createCipheriv('aes-256-gcm', key, iv);
```

### Anti-Pattern 5: Using External TOTP Libraries

```typescript
// WRONG — unnecessary dependency
import { TOTP } from 'otpauth';
const totp = new TOTP({ secret: 'JBSWY3DPEHPK3PXP' });
const code = totp.generate();

// WRONG — another unnecessary dependency
import speakeasy from 'speakeasy';
const token = speakeasy.totp({ secret: userSecret, encoding: 'base32' });

// CORRECT — native implementation per RFC 4226/6238
import { createHmac } from 'node:crypto';
const buf = Buffer.alloc(8);
buf.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000 / 30)));
const hmac = createHmac('sha1', secretBuffer).update(buf).digest();
const offset = hmac[hmac.length - 1] & 0xf;
const code = ((hmac.readUInt32BE(offset) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
```

### Anti-Pattern 6: Storing Tokens in Plaintext

```typescript
// WRONG — if database is compromised, all tokens are exposed
await redis.set(`refresh:${userId}`, rawRefreshToken);

// CORRECT — store SHA-256 hash; raw token returned to user only once
import { createHash, randomBytes } from 'node:crypto';
const rawToken = randomBytes(32).toString('hex');
const hashedToken = createHash('sha256').update(rawToken).digest('hex');
await redis.set(`refresh:${userId}`, hashedToken);
// Return rawToken to user; never store it
```

### Anti-Pattern 7: Importing from 'crypto' Without node: Prefix

```typescript
// WRONG — ambiguous, could resolve to an npm package named "crypto"
import { randomBytes } from 'crypto';

// CORRECT — explicit built-in module reference
import { randomBytes } from 'node:crypto';
```

### Anti-Pattern 8: Weak Encryption Keys

```typescript
// WRONG — predictable, low-entropy key
const key = Buffer.from('my-super-secret-encryption-key!!');  // dictionary words
const key = Buffer.alloc(32, 0);  // all zeros
const key = createHash('sha256').update('password').digest();  // derived from weak input

// CORRECT — generated with CSPRNG
// node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"
const key = Buffer.from(process.env.MFA_ENCRYPTION_KEY!, 'base64');
// Validate at startup: key.length === 32
```

### Anti-Pattern 9: Ignoring Auth Tag in GCM Decryption

```typescript
// WRONG — forgetting to set auth tag allows tampered ciphertext to decrypt
const decipher = createDecipheriv('aes-256-gcm', key, iv);
// Missing: decipher.setAuthTag(authTag);
let decrypted = decipher.update(ciphertext);
decrypted = Buffer.concat([decrypted, decipher.final()]);  // THROWS, but pattern shows intent to skip

// CORRECT — always set and verify auth tag
const decipher = createDecipheriv('aes-256-gcm', key, iv);
decipher.setAuthTag(authTag);  // MUST be set before update/final
let decrypted = decipher.update(ciphertext);
decrypted = Buffer.concat([decrypted, decipher.final()]);  // Verifies tag integrity
```

### Anti-Pattern 10: Using ECB Mode or Deprecated Algorithms

```typescript
// WRONG — ECB mode leaks patterns in ciphertext
const cipher = createCipheriv('aes-256-ecb', key, null);

// WRONG — DES is cryptographically broken
const cipher = createCipheriv('des', key, iv);

// WRONG — MD5 is broken for collision resistance
const hash = createHash('md5').update(data).digest('hex');

// CORRECT — AES-256-GCM for encryption, SHA-256 for hashing
const cipher = createCipheriv('aes-256-gcm', key, randomBytes(12));
const hash = createHash('sha256').update(data).digest('hex');
```

### Anti-Pattern 11: Synchronous scrypt in Request Handlers

```typescript
// WRONG — blocks the event loop for ~100ms per request
import { scryptSync } from 'node:crypto';
const derived = scryptSync(password, salt, 64, { N: 32768, r: 8, p: 1 });

// CORRECT — async scrypt does not block the event loop
// (Node.js runs scrypt on the libuv thread pool)
import { scrypt } from 'node:crypto';
import { promisify } from 'node:util';
const scryptAsync = promisify(scrypt);
const derived = await scryptAsync(password, salt, 64, { N: 32768, r: 8, p: 1 }) as Buffer;
```

---

## Quick Reference Checklist

Use this checklist when writing or reviewing cryptographic code in `@bymax-one/nest-auth`.

### Imports

- [ ] All crypto imports use `node:crypto` prefix (not bare `crypto`)
- [ ] No external crypto packages in `package.json` dependencies
- [ ] `promisify` imported from `node:util` for async scrypt

### Password Hashing (scrypt)

- [ ] Salt: 16 bytes from `randomBytes(16)`, unique per password
- [ ] Parameters: N=32768 (2^15), r=8, p=1, keyLen=64
- [ ] Storage format: `scrypt:{salt_hex}:{derived_hex}`
- [ ] Comparison uses `timingSafeEqual` (not `===` or `Buffer.equals`)
- [ ] Async version used (`promisify(scrypt)`, never `scryptSync` in request handlers)
- [ ] Recovery codes hashed with same scrypt parameters

### AES-256-GCM Encryption

- [ ] Algorithm: `aes-256-gcm`
- [ ] Key: exactly 32 bytes, validated at startup
- [ ] IV: 12 bytes from `randomBytes(12)`, fresh per encryption (NEVER reused)
- [ ] Auth tag: 16 bytes, stored alongside ciphertext
- [ ] Format: `base64(iv):base64(tag):base64(ciphertext)`
- [ ] Auth tag set via `decipher.setAuthTag()` before decryption
- [ ] Decryption errors propagated (never silently caught)

### TOTP/HOTP

- [ ] Algorithm: HMAC-SHA1 (per RFC 4226 — do NOT change to SHA-256)
- [ ] Counter encoded as 8-byte big-endian via `writeBigUInt64BE(BigInt(counter))`
- [ ] Dynamic truncation: `hmac[hmac.length - 1] & 0xf` for offset
- [ ] Code: `(readUInt32BE(offset) & 0x7fffffff) % 10^digits`, zero-padded
- [ ] Default: 6 digits, 30-second period, window of 1
- [ ] Secrets: 20 bytes (160 bits), Base32-encoded for URI
- [ ] Secrets encrypted at rest with AES-256-GCM
- [ ] Replay prevention: used codes stored in Redis for 3 * period TTL

### Token Generation

- [ ] All tokens generated with `randomBytes(32)` minimum
- [ ] Encoding: hex (64 chars) or base64url for URL-safe tokens
- [ ] UUIDs via `crypto.randomUUID()` (not `uuid` package)
- [ ] Tokens stored as SHA-256 hashes, not plaintext
- [ ] `Math.random()` never used for any security value

### OTP Generation

- [ ] Generated with `crypto.randomInt(0, 10 ** length)`
- [ ] Length: 1-8 digits (enforced validation)
- [ ] Zero-padded with `.padStart(length, '0')`
- [ ] `Math.random()` never used

### Hashing (SHA-256)

- [ ] Used only for non-password hashing (tokens, identifiers)
- [ ] Output: hex encoding (64 characters)
- [ ] `createHash('sha256')` — not MD5, not SHA-1

### Timing Safety

- [ ] `timingSafeEqual` used for all secret comparisons
- [ ] Buffer lengths checked before calling `timingSafeEqual`
- [ ] No `===` comparison on secrets, tokens, hashes, or OTP codes

### Key Management

- [ ] Encryption key: 32 bytes from base64, validated at startup
- [ ] JWT secret: minimum 32 characters, Shannon entropy >= 3.5 bits/char
- [ ] Keys loaded from environment variables, never hardcoded
- [ ] Key values never logged (only validation success/failure)

### General

- [ ] No `scryptSync` in request handlers (use async)
- [ ] No ECB mode encryption
- [ ] No DES or MD5
- [ ] No `Math.random()` anywhere in security-critical paths
- [ ] All error messages avoid leaking cryptographic details to end users
