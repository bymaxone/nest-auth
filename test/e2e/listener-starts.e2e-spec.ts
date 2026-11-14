/**
 * @fileoverview Sequential requests do not bind a listener each.
 *
 * supertest 7.3 starts a server that is not listening for every request and closes it when the
 * request settles, so a spec that sends requests one after another binds a new loopback port per
 * request and, under load, runs the ephemeral range dry (`EADDRNOTAVAIL`). `bootstrapTestApp` hands
 * supertest a server that is already listening. These cases count the listeners a run of
 * sequential requests starts: none with the default bootstrap, and one per request without it,
 * which is the behaviour that makes the helper necessary and the case to delete if supertest ever
 * stops doing it.
 */

import { Server } from 'node:net'

import request from 'supertest'

import { bootstrapTestApp } from './setup'

const REQUESTS = 25

describe('listeners started by sequential requests (E2E)', () => {
  afterEach(() => {
    jest.restoreAllMocks()
  })

  // Scenario: an application from the default bootstrap and requests sent one after another.
  // Expected: no listener is started, because the server is already listening on a port of its own.
  it('starts no listener for sequential requests to a listening application', async () => {
    const { app } = await bootstrapTestApp()
    const listen = jest.spyOn(Server.prototype, 'listen')

    for (let sent = 0; sent < REQUESTS; sent += 1) {
      const res = await request(app.getHttpServer()).get('/me')
      expect(res.status).toBe(401)
    }

    expect(listen).not.toHaveBeenCalled()
    await app.close()
  })

  // Scenario: an application that is not listening, which supertest has to start. Expected: one
  // listener per request. This is the premise of the helper, so it fails when supertest changes.
  it('starts a listener per request when the application is not listening', async () => {
    const { app } = await bootstrapTestApp({}, { listen: false })
    const listen = jest.spyOn(Server.prototype, 'listen')

    for (let sent = 0; sent < REQUESTS; sent += 1) {
      await request(app.getHttpServer()).get('/me')
    }

    expect(listen).toHaveBeenCalledTimes(REQUESTS)
    await app.close()
  })
})
