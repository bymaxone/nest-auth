/**
 * @fileoverview Fails when a route mounted behind `WorkspaceGuard` declares no `@WorkspaceRoles`.
 *
 * The guard already closes such a route at request time. This catches the mistake at build time
 * for every controller the library ships, so a forgotten declaration is a red test and not a route
 * that answers `403` to everyone.
 *
 * @layer Test
 */

import { readdirSync } from 'node:fs'
import { join } from 'node:path'

import { Controller, Get, UseGuards } from '@nestjs/common'
import { GUARDS_METADATA } from '@nestjs/common/constants'

import {
  ALLOW_PENDING_WORKSPACE_KEY,
  AllowPendingWorkspace
} from '../decorators/allow-pending-workspace.decorator'
import { WORKSPACE_ROLES_KEY, WorkspaceRoles } from '../decorators/workspace-roles.decorator'
import { WorkspaceGuard } from './workspace.guard'

type Constructor = new (...args: never[]) => object

/** Whether a guard list contains `WorkspaceGuard`. */
function usesGuard(guards: unknown): boolean {
  return Array.isArray(guards) && guards.includes(WorkspaceGuard)
}

/**
 * Names every route of a controller that runs behind `WorkspaceGuard` and has no roles declared on
 * the handler or on the class.
 *
 * @param controller - The controller class.
 * @returns The `Class.method` of each offending route.
 */
function routesWithoutRoles(controller: Constructor): string[] {
  const classGuarded = usesGuard(Reflect.getMetadata(GUARDS_METADATA, controller))
  const classRoles: unknown = Reflect.getMetadata(WORKSPACE_ROLES_KEY, controller)
  const prototype = controller.prototype as Record<string, unknown>

  return Object.getOwnPropertyNames(prototype)
    .filter((name) => name !== 'constructor' && typeof prototype[name] === 'function')
    .filter((name) => {
      const handler = prototype[name] as object
      const guarded = classGuarded || usesGuard(Reflect.getMetadata(GUARDS_METADATA, handler))
      const roles: unknown = Reflect.getMetadata(WORKSPACE_ROLES_KEY, handler) ?? classRoles
      return guarded && !(Array.isArray(roles) && roles.length > 0)
    })
    .map((name) => `${controller.name}.${name}`)
}

/**
 * Names every route of a controller that admits the owner of a workspace pending deletion, whether
 * the marker sits on the handler or on the class.
 *
 * @param controller - The controller class.
 * @returns The `Class.method` of each such route.
 */
function routesAdmittingPending(controller: Constructor): string[] {
  const classMarked = Reflect.getMetadata(ALLOW_PENDING_WORKSPACE_KEY, controller) === true
  const prototype = controller.prototype as Record<string, unknown>

  return Object.getOwnPropertyNames(prototype)
    .filter((name) => name !== 'constructor' && typeof prototype[name] === 'function')
    .filter(
      (name) =>
        classMarked ||
        Reflect.getMetadata(ALLOW_PENDING_WORKSPACE_KEY, prototype[name] as object) === true
    )
    .map((name) => `${controller.name}.${name}`)
}

/** The only shipped routes allowed to admit a workspace pending deletion. */
const ROUTES_ADMITTING_PENDING: string[] = []

describe('WorkspaceGuard route inventory', () => {
  // The check has to be able to fail, or the sweep over the shipped controllers proves nothing.
  describe('the rule itself', () => {
    it('flags a guarded handler with no roles', () => {
      @Controller()
      class Bad {
        @UseGuards(WorkspaceGuard)
        @Get()
        list(): void {}
      }

      expect(routesWithoutRoles(Bad)).toEqual(['Bad.list'])
    })

    it('flags a guarded handler whose roles list is empty', () => {
      @Controller()
      class Empty {
        @UseGuards(WorkspaceGuard)
        @WorkspaceRoles()
        @Get()
        list(): void {}
      }

      expect(routesWithoutRoles(Empty)).toEqual(['Empty.list'])
    })

    it('flags every handler of a guarded class that declares none', () => {
      @UseGuards(WorkspaceGuard)
      @Controller()
      class Whole {
        @Get()
        a(): void {}

        @WorkspaceRoles('owner')
        @Get()
        b(): void {}
      }

      expect(routesWithoutRoles(Whole)).toEqual(['Whole.a'])
    })

    it('accepts roles declared on the class or on the handler', () => {
      @UseGuards(WorkspaceGuard)
      @WorkspaceRoles('owner')
      @Controller()
      class Declared {
        @Get()
        a(): void {}
      }

      @Controller()
      class OnHandler {
        @UseGuards(WorkspaceGuard)
        @WorkspaceRoles('owner')
        @Get()
        a(): void {}
      }

      expect([...routesWithoutRoles(Declared), ...routesWithoutRoles(OnHandler)]).toEqual([])
    })

    it('ignores a route that is not behind the guard', () => {
      @Controller()
      class Open {
        @Get()
        a(): void {}
      }

      expect(routesWithoutRoles(Open)).toEqual([])
    })
  })

  it('finds no shipped controller route behind the guard without roles', async () => {
    const directory = join(__dirname, '../controllers')
    const files = readdirSync(directory).filter((name) => /\.controller\.ts$/.test(name))
    const offenders: string[] = []

    for (const file of files) {
      const loaded = (await import(join(directory, file))) as Record<string, unknown>
      for (const exported of Object.values(loaded)) {
        if (typeof exported === 'function')
          offenders.push(...routesWithoutRoles(exported as Constructor))
      }
    }

    expect(files.length).toBeGreaterThan(0)
    expect(offenders).toEqual([])
  })

  describe('routes that admit a workspace pending deletion', () => {
    // The check has to be able to find the marker, or the sweep below proves nothing.
    it('finds the marker on a handler and on a whole class', () => {
      @Controller()
      class OnHandler {
        @AllowPendingWorkspace()
        @Get()
        a(): void {}

        @Get()
        b(): void {}
      }

      @AllowPendingWorkspace()
      @Controller()
      class OnClass {
        @Get()
        c(): void {}
      }

      expect([...routesAdmittingPending(OnHandler), ...routesAdmittingPending(OnClass)]).toEqual([
        'OnHandler.a',
        'OnClass.c'
      ])
    })

    // Adding the marker to a route is a decision about data that is about to be deleted, so it
    // is listed here by name; a route that gains it without this list changing fails the test.
    it('lists exactly the shipped routes that carry it', async () => {
      const directory = join(__dirname, '../controllers')
      const files = readdirSync(directory).filter((name) => /\.controller\.ts$/.test(name))
      const found: string[] = []

      for (const file of files) {
        const loaded = (await import(join(directory, file))) as Record<string, unknown>
        for (const exported of Object.values(loaded)) {
          if (typeof exported === 'function')
            found.push(...routesAdmittingPending(exported as Constructor))
        }
      }

      expect(found.sort()).toEqual([...ROUTES_ADMITTING_PENDING].sort())
    })
  })
})
