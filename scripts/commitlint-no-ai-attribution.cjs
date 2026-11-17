/**
 * @fileoverview A commitlint plugin that refuses a commit message naming an AI tool as its author or its reviewer.
 * @layer scripts
 *
 * Wire it in the commitlint configuration:
 *
 *   plugins: [require('./scripts/commitlint-no-ai-attribution.cjs')],
 *   rules: { 'no-ai-attribution': [2, 'always'] },
 *
 * A repository on the narrow profile builds the plugin with `require(...).build('narrow')` instead.
 */
'use strict'

/** The strict profile: every repository but the narrow ones. */
const STRICT =
  '(?im)(^[ \\t>]*(co-authored-by|signed-off-by|authored-by)[ \\t]*:[^\\n]*\\b(claude|anthropic|codex|openai|chatgpt|copilot|gemini|cursor|devin|aider|windsurf|codeium|tabnine)\\b|noreply@(anthropic|openai|claude)\\.|\\bgenerated (with|by) (\\[|an? )?(claude|anthropic|codex|openai|chatgpt|copilot|gemini|cursor|devin|aider|windsurf|codeium|tabnine|ai)\\b|(^|[^@\\w])(codex|anthropic|chatgpt)\\b|\\bclaude([^.]|$))'

/** The narrow profile: a repository whose subject matter names the products. */
const NARROW =
  '(?im)(^[ \\t>]*(co-authored-by|signed-off-by|authored-by)[ \\t]*:[^\\n]*\\b(claude|anthropic|codex|openai|chatgpt|copilot|gemini|cursor|devin|aider|windsurf|codeium|tabnine)\\b|noreply@(anthropic|openai|claude)\\.|\\bgenerated (with|by) (\\[|an? )?(claude|anthropic|codex|openai|chatgpt|copilot|gemini|cursor|devin|aider|windsurf|codeium|tabnine|ai)\\b|\\b(claude|codex)\\s*(\\+|and|&|/|,)\\s*(claude|codex)\\b|\\b(claude|codex)\\b[^\\n]{0,20}\\b(reviews?|pass|reviewer|bot|findings?)\\b)'

/**
 * The JavaScript form of a pattern: the leading `(?im)` becomes the `im` flags.
 *
 * @param {string} pattern A pattern as the organisation rulesets carry it.
 * @returns {RegExp} The same pattern as a regular expression.
 */
function compile(pattern) {
  return new RegExp(pattern.slice('(?im)'.length), 'im')
}

/** The line git writes above the diff under `git commit -v`, with exactly this many dashes. */
const SCISSORS = '# ------------------------ >8 ------------------------'

/**
 * The text the rule reads. commitlint's own view of the message (its header, body and footer, which it reads with the
 * comment character of the repository's git configuration) when it gives one; otherwise the raw text, all of it up
 * to the scissors line, so a message the rule cannot split is read whole and not in part.
 *
 * @param {{ raw?: string, header?: string | null, body?: string | null, footer?: string | null }} parsed
 *   The commit as commitlint parsed it.
 * @returns {string} The text to read.
 */
function messageOf(parsed) {
  const parts = [parsed.header, parsed.body, parsed.footer].filter(
    (part) => typeof part === 'string' && part !== '',
  )
  if (parts.length > 0) return parts.join('\n')
  const lines = (parsed.raw ?? '').split(/\r?\n/)
  const end = lines.indexOf(SCISSORS)
  return (end === -1 ? lines : lines.slice(0, end)).join('\n')
}

/**
 * The plugin for one profile.
 *
 * @param {'strict' | 'narrow'} [profile] The profile to apply; strict when omitted.
 * @returns {{ rules: Record<string, (parsed: { raw?: string }) => [boolean, string?]> }} A commitlint plugin.
 */
function build(profile = 'strict') {
  if (profile !== 'strict' && profile !== 'narrow')
    throw new Error('the profile must be strict or narrow')
  const pattern = compile(profile === 'narrow' ? NARROW : STRICT)
  return {
    rules: {
      'no-ai-attribution': (parsed, when = 'always') => {
        if (when !== 'always')
          throw new Error(
            "no-ai-attribution has an always form only: configure it as [2, 'always']",
          )
        const match = pattern.exec(messageOf(parsed))
        if (match === null) return [true]
        const found = match[0].replace(/[\u0000-\u001f\u007f]+/g, ' ').slice(0, 80)
        return [
          false,
          `the message names an AI tool as its author or its reviewer ("${found}"); reword it, no commit does this`,
        ]
      },
    },
  }
}

module.exports = build()
module.exports.build = build
module.exports.patterns = { strict: STRICT, narrow: NARROW }
