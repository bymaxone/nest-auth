import { SKIP_MFA_KEY, SkipMfa } from './skip-mfa.decorator'

describe('SkipMfa decorator', () => {
  // Verifies that applying @SkipMfa() sets SKIP_MFA_KEY metadata to exactly `true`
  // on the decorated method. MfaRequiredGuard reads this flag to bypass the MFA
  // check, so a mutated literal of `false` would silently re-enforce MFA on routes
  // that explicitly opted out (e.g. the challenge endpoint itself).
  it('should set SKIP_MFA_KEY metadata to true on the target method', () => {
    class TestController {
      @(SkipMfa() as MethodDecorator)
      challenge() {}
    }

    const metadata = Reflect.getMetadata(SKIP_MFA_KEY, TestController.prototype.challenge)
    expect(metadata).toBe(true)
  })

  // Verifies that @SkipMfa() also works as a class decorator (it is typed as
  // MethodDecorator & ClassDecorator) and stamps the same `true` flag on the class.
  it('should set SKIP_MFA_KEY metadata to true when applied to a class', () => {
    @(SkipMfa() as ClassDecorator)
    class TestController {}

    const metadata = Reflect.getMetadata(SKIP_MFA_KEY, TestController)
    expect(metadata).toBe(true)
  })

  // Verifies SKIP_MFA_KEY is a unique Symbol (not a plain string), preventing
  // metadata-key collisions with unrelated SetMetadata usage in consumer code.
  it('SKIP_MFA_KEY should be a unique symbol', () => {
    expect(typeof SKIP_MFA_KEY).toBe('symbol')
    expect(SKIP_MFA_KEY.toString()).toBe('Symbol(skipMfa)')
  })
})
