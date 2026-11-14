/**
 * Initialises an application and leaves it listening, so supertest never starts one per request.
 *
 * Layer: e2e support.
 *
 * supertest 7.3 starts a server that is not listening for each request and closes it when the
 * request settles, so a spec that sends requests one after another binds a new loopback port for
 * every one and, under load, runs the ephemeral range dry (`EADDRNOTAVAIL`). A server that is
 * already listening is used as it is and is never closed by supertest, so one listener serves the
 * life of the application and `app.close()` closes it.
 */
import type { INestApplication } from '@nestjs/common'

/**
 * Initialises `app` and starts it listening on a port of its own.
 *
 * `bootstrapTestApp` calls this; an application a spec builds by hand calls it in place of `init()`.
 *
 * @param app - The application, created and not yet initialised.
 */
export async function initAndListen(app: INestApplication): Promise<void> {
  await app.init()
  await app.listen(0)
}
