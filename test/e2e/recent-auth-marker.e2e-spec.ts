/**
 * @fileoverview Which sessions count as proof of a recent real authentication.
 *
 * An account with no local password is held to a temporal proof: the caller must have completed
 * a real authentication a few minutes ago. A session minted without any credential being
 * presented proves nothing about who holds it, so it must not satisfy that proof.
 */
import request from 'supertest'

import { AuthService } from '../../src/server/services/auth.service'
import type { BootstrappedTestApp } from './setup'
import { bootstrapTestApp } from './setup'

/** Registers a dashboard account, strips its local password, and forgets any recent-auth mark. */
async function passwordlessAccount(): Promise<{ boot: BootstrappedTestApp; userId: string }> {
  const boot = await bootstrapTestApp({ tokenDelivery: 'bearer' })
  const reg = await request(boot.app.getHttpServer()).post('/register').send({
    email: 'nobody@example.com',
    password: 'SetupSecret123!',
    name: 'Setup User',
    tenantId: 'tenant-1'
  })
  const { user } = reg.body as { user: { id: string } }
  const stored = boot.repo.users.get(user.id)
  if (stored === undefined) throw new Error('registered user missing from the repository')
  boot.repo.users.set(user.id, { ...stored, passwordHash: null })
  const marks = await boot.redis.keys('*ra:*')
  if (marks.length > 0) await boot.redis.del(...marks)
  return { boot, userId: user.id }
}

describe('recent-authentication proof (E2E)', () => {
  // Scenario: a password-less account whose session came from `issueTokensForUserId`, which
  // takes no credential. Expected: MFA setup is refused as needing re-authentication.
  // Why: that method vouches for no one, so its session must not satisfy the proof.
  it('does not treat an issueTokensForUserId session as a recent real authentication', async () => {
    const { boot, userId } = await passwordlessAccount()

    const result = await boot.app
      .get(AuthService)
      .issueTokensForUserId(userId, 'tenant-1', '127.0.0.1', 'jest')
    const res = await request(boot.app.getHttpServer())
      .post('/mfa/setup')
      .set('Authorization', `Bearer ${result.accessToken}`)
      .send({})
    await boot.app.close()

    expect(res.status).toBe(403)
    expect((res.body as { error?: { code?: string } }).error?.code).toBe(
      'auth.reauthentication_required'
    )
  })

  // Scenario: the same account, registered normally (a credential was presented). Expected: MFA
  // setup is allowed. Why: a real authentication must keep satisfying the proof.
  it('still treats a registration as a recent real authentication', async () => {
    const boot = await bootstrapTestApp({ tokenDelivery: 'bearer' })
    const reg = await request(boot.app.getHttpServer()).post('/register').send({
      email: 'nobody@example.com',
      password: 'SetupSecret123!',
      name: 'Setup User',
      tenantId: 'tenant-1'
    })
    const { user, accessToken } = reg.body as { user: { id: string }; accessToken: string }
    const stored = boot.repo.users.get(user.id)
    if (stored === undefined) throw new Error('registered user missing from the repository')
    boot.repo.users.set(user.id, { ...stored, passwordHash: null })

    const res = await request(boot.app.getHttpServer())
      .post('/mfa/setup')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({})
    await boot.app.close()

    expect(res.status).toBe(201)
  })
})
