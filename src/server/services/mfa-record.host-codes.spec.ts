/**
 * @fileoverview The recovery codes of an account whose entity keeps them on its prototype, through the paths that write
 * the whole MFA record back: what is written is the real list, never an empty one.
 *
 * @layer Test
 */

import { userRecord } from '../utils/__tests__/host-records'
import { guardRepository } from '../utils/host-read'
import { encryptMfaSecret } from '../utils/mfa-secret-cipher'
import { USER_REPOSITORY_CONTRACT } from '../utils/repository-contracts'
import { MfaRecordService } from './mfa-record.service'

const KEYS = { encryptionKey: Buffer.alloc(32, 7).toString('base64') }
const SECRET = 'JBSWY3DPEHPK3PXP'
const DIGESTS = ['digest-1', 'digest-2', 'digest-3']
const OPTIONS = { hmacKey: 'k'.repeat(48), blockedStatuses: [] } as never

/** An entity shaped like an ORM one: every field of the account is an accessor of the prototype over `dataValues`. */
class HydratedAccount {
  constructor(readonly dataValues: Record<string, unknown>) {}
}
for (const field of Object.keys(userRecord()).concat('mfaSecret', 'mfaRecoveryCodes'))
  Object.defineProperty(HydratedAccount.prototype, field, {
    get(this: HydratedAccount): unknown {
      return this.dataValues[field]
    }
  })

describe('MfaRecordService over an entity that keeps its fields on the prototype', () => {
  // Scenario: the secret of an enrolled account is re-encrypted under the current key, which writes the whole MFA record
  // back, and its recovery codes are an accessor of the prototype. Expected: the write carries the real digests. Why:
  // the codes are read from the copy of the record, and a list read as absent would be written back as an empty one and
  // silently wipe the account's recovery codes.
  it('writes the real recovery codes back when the secret is re-encrypted', async () => {
    const entity = new HydratedAccount({
      ...userRecord({ mfaEnabled: true }),
      mfaSecret: encryptMfaSecret(SECRET, KEYS),
      mfaRecoveryCodes: DIGESTS
    })
    const updateMfa = jest.fn().mockResolvedValue(undefined)
    const repository = guardRepository(
      { findById: async (): Promise<unknown> => entity, updateMfa },
      USER_REPOSITORY_CONTRACT
    )
    const redis = {
      setIfAbsent: jest.fn().mockResolvedValue(true),
      eval: jest.fn().mockResolvedValue(1)
    }
    const service = new MfaRecordService(OPTIONS, repository as never, null, redis as never)

    await service.reencryptSecret('u1', 'dashboard', SECRET, 't1', KEYS)

    expect(updateMfa).toHaveBeenCalledTimes(1)
    const written = updateMfa.mock.calls[0]?.[0] as {
      id: string
      tenantId: string
      data: { mfaEnabled: boolean; mfaRecoveryCodes: string[] }
    }
    expect(written.id).toBe('u1')
    expect(written.tenantId).toBe('t1')
    expect(written.data.mfaEnabled).toBe(true)
    expect(written.data.mfaRecoveryCodes).toEqual(DIGESTS)
  })
})
