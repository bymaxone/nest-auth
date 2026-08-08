/**
 * Every DTO that accepts a `tenantId` refuses control characters in it.
 *
 * `tenantId` reaches the logger verbatim on `/login`, `/register`, `/verify-email`,
 * `/password/forgot-password` and `/oauth/:provider` — all `@Public()`. A value carrying a
 * newline writes a second, fabricated record into the operator's SIEM and can truncate the
 * genuine ones around it (ASVS v5 §16.5.1). The constraint is deliberately permissive: it
 * refuses only the characters that forge a record boundary.
 *
 * The check is table-driven over every DTO that carries the field, because the constraint has
 * to hold on all of them or the widest unauthenticated entry point is whichever one was
 * forgotten.
 */

import { plainToInstance } from 'class-transformer'
import { validate } from 'class-validator'

import { ForgotPasswordDto } from './forgot-password.dto'
import { LoginDto } from './login.dto'
import { OAuthInitiateQueryDto } from './oauth-initiate-query.dto'
import { RegisterDto } from './register.dto'
import { ResendOtpDto } from './resend-otp.dto'
import { ResendVerificationDto } from './resend-verification.dto'
import { ResetPasswordDto } from './reset-password.dto'
import { VerifyEmailDto } from './verify-email.dto'
import { VerifyOtpDto } from './verify-otp.dto'

/** The DTOs that accept a `tenantId`, each with a body that is otherwise valid. */
const CASES: ReadonlyArray<readonly [string, new () => object, Record<string, unknown>]> = [
  ['LoginDto', LoginDto, { email: 'a@b.com', password: 'Password1!' }],
  ['RegisterDto', RegisterDto, { email: 'a@b.com', password: 'Password1!', name: 'Someone Real' }],
  ['ForgotPasswordDto', ForgotPasswordDto, { email: 'a@b.com' }],
  ['ResendOtpDto', ResendOtpDto, { email: 'a@b.com' }],
  ['ResendVerificationDto', ResendVerificationDto, { email: 'a@b.com' }],
  ['VerifyEmailDto', VerifyEmailDto, { email: 'a@b.com', otp: '123456' }],
  ['VerifyOtpDto', VerifyOtpDto, { email: 'a@b.com', otp: '123456' }],
  [
    'ResetPasswordDto',
    ResetPasswordDto,
    // `newPassword`, which is what this DTO declares. It read `password` until the positive
    // scenarios below started asserting zero errors: every assertion here was of the form
    // "there is an error on `tenantId`", which a body failing for an unrelated reason satisfies
    // just as well, so the fixture was never valid and nothing said so.
    { email: 'a@b.com', newPassword: 'Password1!', otp: '123456' }
  ],
  ['OAuthInitiateQueryDto', OAuthInitiateQueryDto, {}]
]

/** The control characters that end a record in a line-oriented log pipeline. */
const CONTROL_CHARACTERS: readonly string[] = [
  '\u000A', // line feed
  '\u000D', // carriage return
  '\u0000', // NUL
  '\u007F', // DEL
  '\u0085', // C1 next-line
  '\u0009' // tab
]

describe('tenantId charset', () => {
  // The attack, in the shape an unauthenticated caller would send it.
  it.each(CASES)('%s refuses a tenantId that would forge a log record', async (_n, Dto, body) => {
    const dto = plainToInstance(Dto, {
      ...body,
      tenantId: 'acme\u000ALOG [AuthService] login: success userId=victim'
    })
    const errors = await validate(dto)
    expect(errors.map((e) => e.property)).toContain('tenantId')
  })

  // …and every other control character that can end a record.
  it.each(CONTROL_CHARACTERS)('LoginDto refuses a tenantId containing %j', async (control) => {
    const dto = plainToInstance(LoginDto, {
      email: 'a@b.com',
      password: 'Password1!',
      tenantId: `acme${control}evil`
    })
    const errors = await validate(dto)
    expect(errors.map((e) => e.property)).toContain('tenantId')
  })

  // Deliberately permissive: the constraint stops record forgery, it does not impose a naming
  // scheme. A tenant id this library cannot anticipate must still validate.
  it.each([
    'acme',
    'acme.eu-west-1:prod',
    '3f2504e0-4f89-11d3-9a0c-0305e82c3301',
    'açaí',
    'Acme Corp'
  ])('LoginDto accepts the printable tenantId %j', async (tenantId) => {
    const dto = plainToInstance(LoginDto, {
      email: 'a@b.com',
      password: 'Password1!',
      tenantId
    })
    const errors = await validate(dto)
    // Zero errors, not merely "none on `tenantId`". The weaker assertion passes even when the
    // DTO has started rejecting the payload for some unrelated reason, which is the state a
    // positive case exists to rule out.
    expect(errors).toHaveLength(0)
  })

  // A deployment that configures `tenantIdResolver` has stated that the body's value is ignored,
  // so requiring the field would force every client to send something the server discards. The
  // check is table-driven for the same reason as the one above: the field is optional on all of
  // them or the contract differs per endpoint, and a client cannot tell which is which.
  it.each(CASES)('%s accepts a body that omits tenantId entirely', async (_n, Dto, body) => {
    const dto = plainToInstance(Dto, body)

    const errors = await validate(dto)

    // Zero errors rather than "none on `tenantId`", so a payload rejected for an unrelated
    // reason cannot pass as proof that the field became optional.
    expect(errors).toHaveLength(0)
  })

  // Optional means absent, not empty. A caller that sends the field must still send a usable
  // value: an empty string names no tenant and would scope the request to one nothing owns.
  it.each(CASES)('%s still refuses an empty tenantId', async (_n, Dto, body) => {
    const dto = plainToInstance(Dto, { ...body, tenantId: '' })

    const errors = await validate(dto)

    expect(errors.map((e) => e.property)).toContain('tenantId')
  })
})
