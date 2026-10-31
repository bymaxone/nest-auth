import { Logger } from '@nestjs/common'

import { ApiKeyLastUsedService } from './api-key-last-used.service'
import { KEY_ID, MemoryApiKeyRepository, makeOptions, makeRow } from './__tests__/api-key-fixtures'

const OTHER_ID = '5a1d9e40-7b3c-4f6a-8c21-0e9d4b6a3f12'
const T0 = new Date('2026-06-01T12:00:00.000Z')
const at = (seconds: number): Date => new Date(T0.getTime() + seconds * 1000)

function build(flushSeconds = 60): {
  service: ApiKeyLastUsedService
  repo: MemoryApiKeyRepository
} {
  const repo = new MemoryApiKeyRepository([makeRow(), makeRow({ id: OTHER_ID })])
  const service = new ApiKeyLastUsedService(
    repo,
    makeOptions({ lastUsedFlushSeconds: flushSeconds })
  )
  return { service, repo }
}

beforeEach(() => {
  jest.useFakeTimers()
})

afterEach(() => {
  jest.useRealTimers()
  jest.restoreAllMocks()
})

describe('ApiKeyLastUsedService', () => {
  // The whole point: recording a use does no I/O, however often it happens.
  it('writes nothing when a use is recorded', () => {
    const { service, repo } = build()
    for (let i = 0; i < 1000; i++) service.record(KEY_ID, at(i))
    expect(repo.calls).toEqual([])
  })

  // However many uses arrive in a window, exactly one timer is armed for it.
  it('arms a single timer per window', () => {
    const { service } = build()
    const spy = jest.spyOn(global, 'setTimeout')
    service.record(KEY_ID, at(1))
    service.record(KEY_ID, at(2))
    service.record(OTHER_ID, at(3))
    expect(spy).toHaveBeenCalledTimes(1)
  })

  // After the configured window, every key used in it is written in ONE batch, with its latest use.
  it('flushes once per window with the latest use of each key', async () => {
    const { service, repo } = build()
    service.record(KEY_ID, at(1))
    service.record(KEY_ID, at(5))
    service.record(KEY_ID, at(3))
    service.record(OTHER_ID, at(2))
    await jest.advanceTimersByTimeAsync(59_999)
    expect(repo.calls).toEqual([])
    await jest.advanceTimersByTimeAsync(1)
    expect(repo.calls).toEqual(['touchLastUsed'])
    expect(repo.rows.get(KEY_ID)?.lastUsedAt).toEqual(at(5))
    expect(repo.rows.get(OTHER_ID)?.lastUsedAt).toEqual(at(2))
  })

  // The window length comes from configuration.
  it('honours the configured window', async () => {
    const { service, repo } = build(5)
    service.record(KEY_ID, at(1))
    await jest.advanceTimersByTimeAsync(5000)
    expect(repo.calls).toEqual(['touchLastUsed'])
  })

  // A second window starts only when something is recorded again: an idle process has no timer.
  it('schedules a new window only after the next use', async () => {
    const { service, repo } = build()
    service.record(KEY_ID, at(1))
    await jest.advanceTimersByTimeAsync(60_000)
    await jest.advanceTimersByTimeAsync(120_000)
    expect(repo.calls).toEqual(['touchLastUsed'])
    service.record(KEY_ID, at(200))
    await jest.advanceTimersByTimeAsync(60_000)
    expect(repo.calls).toEqual(['touchLastUsed', 'touchLastUsed'])
  })

  // The timer never keeps the process alive.
  it('unrefs its timer', () => {
    const { service } = build()
    const unref = jest.fn()
    jest.spyOn(global, 'setTimeout').mockReturnValue({ unref } as unknown as NodeJS.Timeout)
    service.record(KEY_ID, at(1))
    expect(unref).toHaveBeenCalledTimes(1)
  })

  // A failed flush keeps the entries, merged by latest use, and retries on the next window.
  it('keeps entries when a flush fails and retries them', async () => {
    const { service, repo } = build()
    const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
    repo.failWith = new Error('db down with secret=SHOULD-NOT-LEAK')
    service.record(KEY_ID, at(1))
    await jest.advanceTimersByTimeAsync(60_000)
    expect(warn).toHaveBeenCalledTimes(1)
    expect(String(warn.mock.calls[0]?.[0])).toContain('api-key: last-used flush failed cause=')
    expect(String(warn.mock.calls[0]?.[0])).not.toContain('SHOULD-NOT-LEAK')
    // Nothing is recorded again: the retry must come from the entries the failure kept.
    repo.failWith = null
    await jest.advanceTimersByTimeAsync(60_000)
    expect(repo.rows.get(KEY_ID)?.lastUsedAt).toEqual(at(1))
  })

  // An empty flush does not touch the store.
  it('does nothing when there is nothing to flush', async () => {
    const { service, repo } = build()
    await service.flush()
    expect(repo.calls).toEqual([])
  })

  // A clean shutdown writes what is left and stops scheduling.
  it('flushes on shutdown and schedules nothing afterwards', async () => {
    const { service, repo } = build()
    service.record(KEY_ID, at(1))
    await service.onApplicationShutdown()
    expect(repo.rows.get(KEY_ID)?.lastUsedAt).toEqual(at(1))
    service.record(KEY_ID, at(9))
    await jest.advanceTimersByTimeAsync(120_000)
    expect(repo.calls).toEqual(['touchLastUsed'])
  })

  // Shutdown with no timer pending and nothing recorded is a no-op.
  it('shuts down cleanly when idle', async () => {
    const { service, repo } = build()
    await expect(service.onApplicationShutdown()).resolves.toBeUndefined()
    expect(repo.calls).toEqual([])
  })
})
