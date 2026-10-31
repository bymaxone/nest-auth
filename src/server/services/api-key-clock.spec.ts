import { SystemApiKeyClock } from './api-key-clock'

describe('SystemApiKeyClock', () => {
  afterEach(() => {
    jest.useRealTimers()
  })

  // It reads the wall clock every call, so a later call is never a cached earlier instant.
  it('returns the current instant on every call', () => {
    jest.useFakeTimers({ now: new Date('2026-06-01T12:00:00.000Z') })
    const clock = new SystemApiKeyClock()
    expect(clock.now()).toEqual(new Date('2026-06-01T12:00:00.000Z'))
    jest.setSystemTime(new Date('2026-06-01T12:00:05.000Z'))
    expect(clock.now()).toEqual(new Date('2026-06-01T12:00:05.000Z'))
  })
})
