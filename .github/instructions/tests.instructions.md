---
applyTo: '**/*.spec.ts,**/*.e2e.spec.ts'
---

# Testing standards

## Coverage gate

`pnpm test:cov:all` enforces **100% statements, branches, functions, and lines**. Any PR that drops coverage below 100% on a touched source file must not be approved — it is a hard pre-publish gate, not a target.

## Mutation testing threshold

Stryker `break: 95` is the enforced gate (aspirational `high: 99`). Flag tests that use generic matchers (`toBeDefined()`, `toBeTruthy()`) where a value assertion is possible — they survive Stryker mutants.

## Test structure and naming

```
describe('ClassName')           →  class under test
  describe('#methodName()')     →  instance method (use . for static)
    it('should <outcome> when <condition>')
```

Every `it` must state the expected behaviour. Avoid `it('works')` or `it('returns value')`.

## Scope: public API only

Test through exported public interfaces only. Never access private class members or unexported internals. If behaviour is only verifiable through a private member, the design needs refactoring.

## Mutation-aware assertion patterns (required to kill Stryker mutants)

**1. Assert the value, not just existence:**

```typescript
// ❌ expect(result).toBeDefined()  — survives a value mutation
// ✅ expect(result.accessToken).toMatch(/^eyJ/)
```

**2. Test BOTH sides of every `||` / `&&`:**

```typescript
// Source: if (isValidTenant && isActiveSession) — add a test with only one side true
// to kill the && → || mutation
```

**3. Assert error code AND message independently:**

```typescript
// kills the code mutant and the message mutant separately
expect(err.code).toBe(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
expect(err.message).toContain('credentials')
```

**4. Cover the acceptance path of every guard/predicate:**

```typescript
// ❌ only testing rejection: the ArrowFunction `() => false` mutation survives
// ✅ also assert the allow path: expect(guard.canActivate(ctx)).toBe(true)
```

## Stryker disable comments

Equivalent mutants only: `// Stryker disable next-line <Mutator>: <reason why mutant is equivalent>`. Prefer documenting equivalents in a results doc over inline comments where the bundle ships unminified.

## Security-path test requirements

- **Timing-safe comparisons**: assert that secret/token/OTP comparison rejects a wrong value of the SAME length (not just a length mismatch) — this is what `timingSafeEqual` protects.
- **Multi-tenant isolation**: every repository-backed feature needs a test proving a cross-tenant access (right id, wrong `tenantId`) is rejected.
- **MFA/crypto**: test both correct and incorrect TOTP codes, and that MFA secrets are never returned/logged in plaintext.
- **Brute-force**: assert the throttle/lockout triggers at the configured threshold AND that a legitimate retry under the threshold succeeds.

## NestJS integration tests

Use `@nestjs/testing → Test.createTestingModule(...)`. Override only external I/O — Redis via `ioredis-mock`, the email provider, the consumer-supplied repository. Keep all DI wiring real; do not stub the library's own services.

## E2E tests (`*.e2e.spec.ts`)

Real NestJS app (`NestFactory.create`) + `supertest`. Must validate end-to-end: guards reject unauthenticated/cross-tenant requests, login issues access+refresh tokens, refresh rotation works, and revocation (JTI blacklist) blocks a revoked token.

## React / Next.js tests

- React hooks/components (`./react`) use `@testing-library/react` + `jest-environment-jsdom`.
- Restore all mocks in `afterEach` / `afterAll` — never leave module-level mocks bleeding across files.
- Never assert on fabricated class names or implementation details; assert on observable behaviour and accessible output.
