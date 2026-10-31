/**
 * @fileoverview Coalesces "last used" timestamps so a verified request costs no write.
 *
 * @layer Service
 */

import { Inject, Injectable, Logger } from '@nestjs/common'
import type { OnApplicationShutdown } from '@nestjs/common'

import { BYMAX_AUTH_API_KEY_REPOSITORY, BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import type { IApiKeyRepository } from '../interfaces/api-key-repository.interface'
import { describeChannelStatus } from '../utils/describe-error'

/**
 * Remembers the latest use of each key in memory and writes them to the store in one batch per
 * window.
 *
 * A verified request does a `Map` write and nothing else. The trade-off is stated in the
 * README: with N instances a key is written up to N times per window, and a crash loses at most
 * one window of an advisory timestamp. Authorization never reads this, so a lost or late value
 * cannot admit or refuse anything.
 */
@Injectable()
export class ApiKeyLastUsedService implements OnApplicationShutdown {
  private readonly logger = new Logger(ApiKeyLastUsedService.name)
  private pending = new Map<string, Date>()
  private timer: NodeJS.Timeout | null = null
  private closed = false

  constructor(
    @Inject(BYMAX_AUTH_API_KEY_REPOSITORY) private readonly repository: IApiKeyRepository,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions
  ) {}

  /**
   * Notes that a key verified at an instant. Synchronous and free of I/O.
   *
   * @param id - The key's row id.
   * @param at - When it verified.
   */
  record(id: string, at: Date): void {
    const seen = this.pending.get(id)
    // Stryker disable next-line EqualityOperator: at equal instants either Date is the same time, so which one is kept is not observable
    if (seen === undefined || seen.getTime() < at.getTime()) this.pending.set(id, at)
    if (this.timer === null && !this.closed) {
      // Unref'd: a pending flush must never be the reason a process stays alive.
      this.timer = setTimeout(() => {
        this.timer = null
        void this.flush()
      }, this.options.apiKeys.lastUsedFlushSeconds * 1000)
      this.timer.unref()
    }
  }

  /**
   * Writes everything pending in one batch. A failure keeps the entries for the next window.
   *
   * @returns Resolves once the batch is written or has been put back.
   */
  async flush(): Promise<void> {
    if (this.pending.size === 0) return
    const batch = this.pending
    this.pending = new Map()
    try {
      await this.repository.touchLastUsed([...batch].map(([id, at]) => ({ id, at })))
    } catch (err: unknown) {
      this.logger.warn(`api-key: last-used flush failed cause=${describeChannelStatus(err)}`)
      for (const [id, at] of batch) this.record(id, at)
    }
  }

  /** Flushes what is left so a clean shutdown loses nothing. */
  async onApplicationShutdown(): Promise<void> {
    this.closed = true
    if (this.timer !== null) clearTimeout(this.timer)
    this.timer = null
    await this.flush()
  }
}
