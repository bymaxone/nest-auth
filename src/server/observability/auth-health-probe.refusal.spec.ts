/**
 * @fileoverview What the readiness probe rejects with when the client's call fails: the client's error can hold
 * the command it failed and its arguments, so none of it is carried. A real client talks to a loopback server
 * that refuses its handshake.
 *
 * @layer Test
 */

import { createServer } from 'node:net'
import type { AddressInfo, Server, Socket } from 'node:net'
import { inspect } from 'node:util'

import { Redis } from 'ioredis'

import { AuthHealthProbe } from './auth-health-probe'

const PASSWORD = 'dummy-password-7f3a'

/** The reply of a store to one command, by the command's name and arguments. */
type Answer = (name: string, args: string[]) => string

const WRONG_PASSWORD: Answer = (name) =>
  name === 'hello' || name === 'auth'
    ? '-WRONGPASS invalid username-password pair or user is disabled.\r\n'
    : '-NOAUTH Authentication required.\r\n'

/** A server that does not know `AUTH` and repeats the arguments in its refusal, as Redis does for such a command. */
const ECHOING: Answer = (name, args) =>
  name === 'hello' || name === 'auth'
    ? `-ERR unknown command '${name}', with args beginning with: ${args.map((a) => `'${a}'`).join(' ')}\r\n`
    : '-NOAUTH Authentication required.\r\n'

/** Writes one reply for every command of a chunk. */
function answerOn(socket: Socket, answer: Answer): void {
  socket.on('data', (chunk) => {
    for (const frame of chunk.toString().split(/(?=\*\d+\r\n)/)) {
      const [name, ...args] = frame.split('\r\n').filter((_, i) => i >= 2 && i % 2 === 0)
      if (name !== undefined) socket.write(answer(name.toLowerCase(), args))
    }
  })
}

describe('AuthHealthProbe refusals', () => {
  let server: Server | undefined
  let client: Redis | undefined
  const sockets: Socket[] = []

  afterEach(async () => {
    client?.disconnect()
    for (const socket of sockets.splice(0)) socket.destroy()
    await new Promise((resolve) => (server ? server.close(resolve) : resolve(undefined)))
    jest.restoreAllMocks()
  })

  /** A client with a password, connected to a loopback server that answers with `answer`. */
  async function clientOf(answer: Answer): Promise<Redis> {
    server = createServer((socket) => {
      sockets.push(socket)
      answerOn(socket, answer)
    })
    await new Promise<void>((resolve) => server?.listen(0, '127.0.0.1', resolve))
    jest.spyOn(console, 'warn').mockImplementation(() => undefined)
    client = new Redis({
      host: '127.0.0.1',
      port: (server.address() as AddressInfo).port,
      password: PASSWORD,
      maxRetriesPerRequest: 1,
      commandTimeout: 1000,
      retryStrategy: () => 50
    })
    client.on('error', () => undefined)
    return client
  }

  /** What `work` rejects with. */
  async function rejectionOf(work: Promise<unknown>): Promise<Error> {
    try {
      await work
    } catch (error: unknown) {
      return error as Error
    }
    throw new Error('resolved')
  }

  /** The rejection holds the library's message and nothing of the client's error. */
  function expectOnly(error: Error, message: string): void {
    expect(error.message).toBe(message)
    expect(Object.keys(error)).toEqual([])
    expect('cause' in error).toBe(false)
    expect(inspect(error, { depth: Infinity, showHidden: true })).not.toContain(PASSWORD)
    expect(JSON.stringify(error)).not.toContain(PASSWORD)
  }

  // Scenario: the store refuses the credentials, and a server whose refusal repeats the arguments of AUTH. Expected:
  // the rejection names the reply code and nothing else the client or the server said.
  it.each([
    ['refuses the credentials', WRONG_PASSWORD, /\((NOAUTH|WRONGPASS)\)/],
    ['repeats the arguments in its refusal', ECHOING, /\((NOAUTH|ERR)\)/]
  ])('carries only the reply code when the store %s', async (_case, answer, code) => {
    const probe = new AuthHealthProbe(await clientOf(answer))

    const error = await rejectionOf(probe.ping())

    expect(error.message).toMatch(code)
    expectOnly(error, `The authentication store failed the PING ${code.exec(error.message)?.[0]}.`)
  })

  // Scenario: the client fails the call in each of the ways it can, with the password planted where an error of the
  // client can hold text. Expected: a reply code or a kind of outage when the error names one, and otherwise neither.
  it.each([
    ['a reply code', 'ReplyError', `OOM ${PASSWORD}`, ' (OOM)'],
    ['a reply that starts with no code', 'ReplyError', `${PASSWORD} refused`, ''],
    ['a reply whose first word only starts as a code', 'ReplyError', `ERRx${PASSWORD}`, ''],
    ['a reply whose first word only ends as a code', 'ReplyError', `${PASSWORD}ERR no`, ''],
    ['a closed connection', 'Error', 'Connection is closed.', ' (closed)'],
    ['an error that is not a reply', 'Error', `ERR ${PASSWORD}`, '']
  ])('names %s and nothing else of the error', async (_case, name, message, reason) => {
    const failure = Object.assign(new Error(message), { name, command: { args: [PASSWORD] } })
    const probe = new AuthHealthProbe({ ping: () => Promise.reject(failure) })

    const error = await rejectionOf(probe.ping())

    expectOnly(error, `The authentication store failed the PING${reason}.`)
  })

  // Scenario: the client throws instead of returning a promise, with something that is not an error. Expected: the
  // same refusal, and nothing of what was thrown.
  it('carries nothing of what a throwing client throws', async () => {
    const probe = new AuthHealthProbe({
      ping: () => {
        // A client may throw anything.
        throw PASSWORD
      }
    })

    expectOnly(await rejectionOf(probe.ping()), 'The authentication store failed the PING.')
  })
})
