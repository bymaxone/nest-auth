/**
 * @fileoverview Tests for the cursor bound of the workspace page query: the one the cursor codec
 * reads, so a cursor the library issues is always one this accepts.
 *
 * @layer Test
 */

import 'reflect-metadata'

import { plainToInstance } from 'class-transformer'
import { validateSync } from 'class-validator'

import { WORKSPACE_CURSOR_MAX_LENGTH } from '../utils/workspace-cursor'
import { WorkspacePageQueryDto } from './workspace-page-query.dto'

/** The validation errors a query string produces, by property. */
function errorsOf(query: Record<string, unknown>): string[] {
  return validateSync(plainToInstance(WorkspacePageQueryDto, query)).map((error) => error.property)
}

describe('WorkspacePageQueryDto cursor', () => {
  // Scenario: a cursor of exactly the codec's maximum, and one character over. Expected: the maximum
  // is accepted and one more is refused, so the DTO and the codec share one bound.
  it('accepts a cursor of the codec maximum and refuses one character more', () => {
    expect(errorsOf({ cursor: 'A'.repeat(WORKSPACE_CURSOR_MAX_LENGTH) })).toEqual([])
    expect(errorsOf({ cursor: 'A'.repeat(WORKSPACE_CURSOR_MAX_LENGTH + 1) })).toEqual(['cursor'])
  })

  // Scenario: a cursor longer than the old 512-character bound. Expected: accepted, since a cursor
  // the library issues for long ids is longer than that.
  it('accepts a cursor of 600 characters', () => {
    expect(errorsOf({ cursor: 'A'.repeat(600) })).toEqual([])
  })
})
