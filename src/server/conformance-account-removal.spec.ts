/**
 * @fileoverview The account-removal section of the shared wire contract: which workspaces stop an
 * account deletion, and the rules the library states for the rest.
 *
 * @layer Test
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { AUTH_ERROR_CODES } from './errors/auth-error-codes'
import { build, code } from './services/__tests__/membership-service-harness'
import { CONTEXT, workspaceRow } from './services/__tests__/workspace-service-harness'
import type { WorkspaceStatus } from './interfaces/workspace-repository.interface'

interface BlockingVector {
  workspaceStatus: WorkspaceStatus
  accountIsSoleOwner: boolean
  blocks: boolean
}

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/wire-contract.json'), 'utf8')
) as {
  workspaceAccountRemoval: { rules: Record<string, string>; blockingVectors: BlockingVector[] }
}
const section = contract.workspaceAccountRemoval

describe('workspace account removal conformance', () => {
  it('states every rule the library follows', () => {
    expect(Object.keys(section.rules).sort()).toEqual([
      'atomicity',
      'audit',
      'blocking',
      'cache',
      'pendingDeletion',
      'scope'
    ])
  })

  it.each(section.blockingVectors)(
    'answers a $workspaceStatus workspace owned alone: $accountIsSoleOwner, blocks: $blocks',
    async ({ workspaceStatus, accountIsSoleOwner, blocks }) => {
      const { service, memberships } = build()
      memberships['listSoleOwned']?.mockResolvedValue({
        items: accountIsSoleOwner ? [workspaceRow({ status: workspaceStatus })] : [],
        nextCursor: null
      })

      const outcome = await code(service.removeAllForUser('t1', 'u9', null, CONTEXT))

      expect(outcome).toBe(blocks ? AUTH_ERROR_CODES.LAST_OWNER : 'ok')
    }
  )
})
