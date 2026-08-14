/**
 * @fileoverview The address-change flow, over HTTP — the endpoint pair nothing drove.
 *
 * `EmailChangeController` sat at **0% functions** in the e2e-only report: both handlers were
 * proven by unit tests calling the method directly, so nothing had ever established that the
 * routes are mounted, that the guards in front of them admit and refuse the right callers, or
 * that the flow composes end to end. The flow changes the address an account recovers through,
 * which makes "the code runs" the least interesting thing that could be true about it.
 *
 * The chain is driven the way a user experiences it: request the change with the current
 * password, read the token out of the message sent to the NEW address, confirm it, and sign in
 * with the address that was just adopted.
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { BYMAX_AUTH_EMAIL_PROVIDER } from '../../src/server/bymax-auth.constants'
import type { BootstrappedTestApp, CapturedEmail, MockEmailProvider } from './setup'
import { bootstrapTestApp, createMockEmailProvider, expectAuthError } from './setup'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PASSWORD = 'Email-Change-Flow-Passphrase'
const ORIGINAL_EMAIL = 'original@example.com'
const NEW_EMAIL = 'adopted@example.com'
const TENANT = 'tenant-1'

/**
 * An email provider that implements the address-change methods and keeps the raw token.
 *
 * `sendEmailChangeVerification` is OPTIONAL on `IEmailProvider`, and the shared mock does not
 * implement it — which `EmailChangeService.onModuleInit` refuses at boot, deliberately: a
 * deployment that cannot deliver the token would otherwise mint `ec:` keys nobody ever receives,
 * a failure that looks like success from every side. So the provider is built here, and the
 * refusal is asserted in its own case below rather than worked around silently.
 */
interface ChangeCapturingProvider extends MockEmailProvider {
  /** Raw tokens handed to `sendEmailChangeVerification`, newest last. */
  readonly changeTokens: string[]
  /** Addresses notified that a change completed. */
  readonly notified: string[]
}

function createChangeCapturingProvider(): ChangeCapturingProvider {
  const base = createMockEmailProvider()
  const changeTokens: string[] = []
  const notified: string[] = []

  return Object.assign(base, {
    changeTokens,
    notified,
    async sendEmailChangeVerification(_tenantId: string, to: string, token: string): Promise<void> {
      changeTokens.push(token)
      base.sentEmails.push({ to, subject: 'Confirm your new address', html: '<p>token</p>' })
    },
    async sendEmailChangedNotification(_tenantId: string, to: string): Promise<void> {
      notified.push(to)
      base.sentEmails.push({ to, subject: 'Your address changed', html: '<p>changed</p>' })
    }
  })
}

/** Boots an application with the address-change surface registered. */
async function bootstrapWithEmailChange(
  email: MockEmailProvider
): Promise<BootstrappedTestApp & { emails: CapturedEmail[] }> {
  const boot = await bootstrapTestApp(
    {},
    {
      controllers: {
        auth: true,
        mfa: true,
        passwordReset: true,
        sessions: true,
        emailChange: true
      },
      extraModuleProviders: [{ provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: email }]
    }
  )

  return Object.assign(boot, { emails: email.sentEmails })
}

/** Registers the account this suite moves, and returns its access token. */
async function registerOriginal(app: INestApplication): Promise<string> {
  const res = await request(app.getHttpServer())
    .post('/register')
    .send({ email: ORIGINAL_EMAIL, password: PASSWORD, name: 'Address Owner', tenantId: TENANT })

  expect(res.status).toBe(201)
  return res.body.accessToken as string
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('email change flow (E2E)', () => {
  describe('the whole chain', () => {
    let app: INestApplication
    let provider: ChangeCapturingProvider
    let accessToken: string

    beforeAll(async () => {
      provider = createChangeCapturingProvider()
      const boot = await bootstrapWithEmailChange(provider)
      app = boot.app
      accessToken = await registerOriginal(app)
    })

    afterAll(async () => {
      await app.close()
    })

    // Verifies the request answers 204 and says nothing else. The response deliberately does not
    // report whether a verification went out: the states it would describe (the address is
    // taken, the password was wrong) are already errors, and anything beyond that describes an
    // account's state to whoever holds its token.
    it('answers a change request with 204 and an empty body', async () => {
      const res = await request(app.getHttpServer())
        .post('/email/change')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ newEmail: NEW_EMAIL, currentPassword: PASSWORD })

      expect(res.status).toBe(204)
      expect(res.body).toEqual({})
    })

    // Verifies the token goes to the NEW address and nowhere else. Sending it to the address on
    // file would make the flow provable by whoever already controls the account, which is
    // exactly the party the second factor is not meant to be.
    it('mails the token to the new address, not the current one', () => {
      const sent = provider.sentEmails.filter((mail) => mail.subject === 'Confirm your new address')

      expect(sent).toHaveLength(1)
      expect(sent[0]!.to).toBe(NEW_EMAIL)
      expect(provider.changeTokens).toHaveLength(1)
    })

    // Verifies the address has NOT moved yet. Without this the confirmation below would prove
    // nothing — a flow that changed the address on request and mailed a token for decoration
    // would pass every other case here.
    it('has not moved the address before the token is spent', async () => {
      const withNew = await request(app.getHttpServer())
        .post('/login')
        .send({ email: NEW_EMAIL, password: PASSWORD, tenantId: TENANT })

      expectAuthError(withNew, 'auth.invalid_credentials')

      const withOriginal = await request(app.getHttpServer())
        .post('/login')
        .send({ email: ORIGINAL_EMAIL, password: PASSWORD, tenantId: TENANT })

      expect(withOriginal.status).toBe(200)
    })

    // The confirmation, and the state it produces: the new address signs in, the old one no
    // longer does. Asserting both directions is the point — an implementation that added the new
    // address without retiring the old one would leave two working credentials for one account.
    it('adopts the new address when the token is confirmed', async () => {
      const confirm = await request(app.getHttpServer())
        .post('/email/change/confirm')
        .send({ token: provider.changeTokens[0] })

      expect(confirm.status).toBe(204)

      const withNew = await request(app.getHttpServer())
        .post('/login')
        .send({ email: NEW_EMAIL, password: PASSWORD, tenantId: TENANT })

      expect(withNew.status).toBe(200)

      const withOriginal = await request(app.getHttpServer())
        .post('/login')
        .send({ email: ORIGINAL_EMAIL, password: PASSWORD, tenantId: TENANT })

      expectAuthError(withOriginal, 'auth.invalid_credentials')
    })

    // Verifies the token is single-use, over HTTP. The service spends it with an atomic
    // `getdel`, and this is what shows a replayed link cannot move the address a second time —
    // the one property a mailed credential has to have.
    it('refuses the same token a second time', async () => {
      const replay = await request(app.getHttpServer())
        .post('/email/change/confirm')
        .send({ token: provider.changeTokens[0] })

      expectAuthError(replay, 'auth.email_change_token_invalid')
    })

    // Verifies the confirm route is genuinely public: it is reached with no credential at all,
    // because the person holding the token is proving control of a mailbox rather than of a
    // session. A guard here would break the case the flow exists for — confirming from the
    // device the new mail is on.
    it('answers the confirm route without any credential', async () => {
      const res = await request(app.getHttpServer())
        .post('/email/change/confirm')
        .send({ token: 'f'.repeat(64) })

      expectAuthError(res, 'auth.email_change_token_invalid')
    })
  })

  describe('refusals', () => {
    let app: INestApplication
    let provider: ChangeCapturingProvider
    let accessToken: string

    beforeAll(async () => {
      provider = createChangeCapturingProvider()
      const boot = await bootstrapWithEmailChange(provider)
      app = boot.app
      accessToken = await registerOriginal(boot.app)
    })

    afterAll(async () => {
      await app.close()
    })

    // Verifies the request route is behind a credential. The account is taken from the verified
    // JWT and never from the body, so an unauthenticated caller has no account to name — and the
    // refusal is the authentication one.
    it('refuses a change request with no credential', async () => {
      const res = await request(app.getHttpServer())
        .post('/email/change')
        .send({ newEmail: NEW_EMAIL, currentPassword: PASSWORD })

      expectAuthError(res, 'auth.token_invalid')
    })

    // Verifies the current password is what authorises the move, not merely holding a session.
    // A live access token is not enough: whoever picked up an unlocked laptop has one.
    it('refuses a change request carrying the wrong password', async () => {
      const res = await request(app.getHttpServer())
        .post('/email/change')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ newEmail: NEW_EMAIL, currentPassword: `${PASSWORD}-wrong` })

      expectAuthError(res, 'auth.invalid_credentials')
      expect(provider.changeTokens).toHaveLength(0)
    })

    // Verifies the body cannot name the account. `userId` is not a field of `ChangeEmailDto`,
    // and the pipe refuses unknown properties — so the attempt is rejected as a validation error
    // naming the field, rather than being silently ignored and read from the JWT anyway. The
    // distinction matters: silent ignoring is what makes a spoofing attempt look accepted.
    it('refuses a change request that tries to name another account', async () => {
      const res = await request(app.getHttpServer())
        .post('/email/change')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ newEmail: NEW_EMAIL, currentPassword: PASSWORD, userId: 'user-2' })

      expectAuthError(res, 'auth.validation')

      const body = res.body as { error: { details: unknown } }
      expect(body.error.details).toContainEqual(expect.objectContaining({ field: 'userId' }))
    })
  })

  // Verifies the boot-time refusal that keeps this flow from failing silently. An email provider
  // with no `sendEmailChangeVerification` cannot deliver the token, and the service refuses to
  // start rather than minting `ec:` keys nobody receives — a failure that looks like success from
  // every side and reaches the user as a message that simply never arrives.
  //
  // Driven here rather than in a unit spec because what is being asserted is that the check runs
  // during application bootstrap: `onModuleInit` is the framework's call, not ours.
  it('refuses to boot when the provider cannot deliver the token', async () => {
    await expect(bootstrapWithEmailChange(createMockEmailProvider())).rejects.toThrow(
      /sendEmailChangeVerification/
    )
  })
})
