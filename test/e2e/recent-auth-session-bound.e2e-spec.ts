/**
 * @fileoverview The recent-authentication proof belongs to the session that earned it.
 *
 * An account with no local password is held to a temporal proof: a real authentication a few
 * minutes ago. That proof must be the caller's own. Another session of the same account, one that
 * presented no credential itself, must not borrow it.
 */
import request from 'supertest'

import { AuthService } from '../../src/server/services/auth.service'
import type { BootstrappedTestApp } from './setup'
import { bootstrapTestApp } from './setup'

interface Session {
  accessToken: string
  refreshToken: string
}

/** The account's first session: a registration presents a credential, so it earns the proof. */
async function registerPasswordless(): Promise<{
  boot: BootstrappedTestApp
  userId: string
  earned: Session
}> {
  const boot = await bootstrapTestApp({ tokenDelivery: 'bearer' })
  const reg = await request(boot.app.getHttpServer()).post('/register').send({
    email: 'nobody@example.com',
    password: 'SetupSecret123!',
    name: 'Setup User',
    tenantId: 'tenant-1'
  })
  const body = reg.body as { user: { id: string } } & Session
  const stored = boot.repo.users.get(body.user.id)
  if (stored === undefined) throw new Error('registered user missing from the repository')
  boot.repo.users.set(body.user.id, { ...stored, passwordHash: null })
  return { boot, userId: body.user.id, earned: body }
}

async function setupMfa(boot: BootstrappedTestApp, accessToken: string): Promise<number> {
  const res = await request(boot.app.getHttpServer())
    .post('/mfa/setup')
    .set('Authorization', `Bearer ${accessToken}`)
    .send({})
  return res.status
}

describe('recent-authentication proof is session-bound (E2E)', () => {
  // Scenario: one session earned the proof; a second session of the same account, issued without
  // a credential, asks for MFA setup. Expected: refused as needing re-authentication.
  // Why: the proof is the earning session's, so another session cannot ride it.
  it('does not let another session of the account use a proof it did not earn', async () => {
    const { boot, userId } = await registerPasswordless()

    const other = await boot.app
      .get(AuthService)
      .issueTokensForUserId(userId, 'tenant-1', '127.0.0.1', 'jest')
    const status = await setupMfa(boot, other.accessToken)
    await boot.app.close()

    expect(status).toBe(403)
  })

  // Scenario: the session that earned the proof, as issued and after a refresh. Expected: allowed.
  // Why: rotating the earning session keeps it the same session, so it keeps its proof.
  it('keeps the proof for the session that earned it, through a refresh', async () => {
    const { boot, earned } = await registerPasswordless()

    const refreshed = await request(boot.app.getHttpServer())
      .post('/refresh')
      .send({ refreshToken: earned.refreshToken })
    const rotated = (refreshed.body as Session).accessToken
    const status = await setupMfa(boot, rotated)
    await boot.app.close()

    expect(refreshed.status).toBe(200)
    expect(status).toBe(201)
  })
})
