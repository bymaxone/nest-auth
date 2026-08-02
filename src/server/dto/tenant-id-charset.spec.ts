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
    { email: 'a@b.com', password: 'Password1!', otp: '123456' }
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
})
