/**
 * @fileoverview The query of the two paginated workspace lists: a positional cursor and a page size.
 *
 * @layer DTO
 */

import { IsNotEmpty, IsOptional, IsString, Matches, MaxLength } from 'class-validator'

import { NO_CONTROL_CHARACTERS } from './no-control-characters'

/**
 * Query parameters of the two paginated workspace lists (`GET /workspaces` and
 * `GET /workspaces/:workspaceId/members`).
 *
 * The cursor is positional only: it says where the next page starts, and the tenant and workspace
 * of a list always come from the verified token and the guarded route, never from it. Its content
 * is opaque to the library, so only its shape is checked here.
 *
 * @layer DTO
 */
export class WorkspacePageQueryDto {
  /**
   * The `nextCursor` of the previous page; absent for the first page.
   *
   * `@MaxLength(512)` keeps an oversized value away from the repository.
   */
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @MaxLength(512)
  @Matches(NO_CONTROL_CHARACTERS, { message: 'cursor must not contain control characters' })
  cursor?: string

  /**
   * Page size, a whole number from 1 to 100. Default: 50.
   *
   * A query string value, so it is a string here and the pattern is the range check.
   */
  @IsOptional()
  @IsString()
  @Matches(/^(?:[1-9][0-9]?|100)$/, { message: 'limit must be a whole number from 1 to 100' })
  limit?: string
}
