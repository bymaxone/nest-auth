/**
 * @fileoverview The README's Quick Start code blocks, taken from the README text.
 * @layer test
 *
 * Shared by the specs that execute and type-check the Quick Start, so both read the same blocks
 * the same way and neither keeps a copy that could drift from the README.
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const README = readFileSync(join(__dirname, '../../README.md'), 'utf8')

const QUICK_START_START = '## 🚀 Quick Start'
const QUICK_START_END = '## ⚙️ Configuration'

/** The top-level `typescript` fences of the Quick Start, in the order the README shows them. */
function quickStartBlocks(): string[] {
  const start = README.indexOf(QUICK_START_START)
  const end = README.indexOf(QUICK_START_END)
  if (start === -1 || end === -1) throw new Error('README has no Quick Start section')
  // Anchored to the line start so a fence inside a blockquote is not one of these.
  return Array.from(
    README.slice(start, end).matchAll(/^```typescript\n([\s\S]*?)^```$/gm),
    (match) => match[1] ?? ''
  )
}

/** The one block that contains `marker`; zero or several is a README this suite cannot read. */
function block(marker: string): string {
  const found = quickStartBlocks().filter((candidate) => candidate.includes(marker))
  if (found.length !== 1) {
    throw new Error(`Expected one Quick Start block containing "${marker}", found ${found.length}`)
  }
  return found[0] as string
}

export { quickStartBlocks, block }
