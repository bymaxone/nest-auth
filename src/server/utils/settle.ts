/**
 * @fileoverview Waiting for several calls, and for a deadline, without reading a static of `Promise`.
 *
 * `Promise.all` and `Promise.race` are properties of a global that anything running in the process can replace after the library
 * loaded, and a replaced one decides what a read of a repository answered: a membership the store never returned, a profile the
 * plugin never fetched, the order in which sessions are evicted. The root guard does not compare them, because the
 * monitors and the test doubles of a host wrap them and the library has no way to tell those from an attack. So no decision of the
 * library goes through one. These helpers wait with `await` alone, which reads `Promise.prototype.constructor` and nothing else,
 * and that is the one property of `Promise` the baseline compares.
 *
 * @layer Utility
 */

/** The constructor as it was when this module loaded, so a replaced global does not choose what the deadline builds. */
const CapturedPromise = Promise

/** Takes a rejection so that it is never reported as unhandled while another call is being waited for. */
const ignore = (): void => undefined

/**
 * Starts waiting for one call: the answer is a native promise whose rejection is already taken, so it can be awaited later,
 * after another call, with no unhandled rejection in between.
 *
 * @param work - The call, or its value.
 * @returns A promise that settles as the call does.
 */
export function started<T>(work: PromiseLike<T> | T): Promise<T> {
  const settled = (async (): Promise<T> => await work)()
  settled.catch(ignore)
  return settled
}

/**
 * Waits for every call, in order, and answers their values in that order. The calls run together because each one was started
 * before the first is awaited; the first rejection in the order is the one that is thrown, after the calls before it settled.
 *
 * @param calls - The calls, already started.
 * @returns Their values.
 * @throws The reason of the first call in the list that rejected.
 */
export async function allOf<T>(calls: readonly (PromiseLike<T> | T)[]): Promise<T[]> {
  const pending: Promise<T>[] = []
  for (let index = 0; index < calls.length; index += 1) pending.push(started(calls[index] as T))
  const values: T[] = []
  for (let index = 0; index < pending.length; index += 1)
    values.push(await (pending[index] as Promise<T>))
  return values
}

/**
 * Runs the work and rejects when it has not settled within the deadline.
 *
 * The work is not cancelled: the library stops waiting for it.
 *
 * @param work - The calls to bound.
 * @param ms - The deadline in milliseconds.
 * @param message - The message of the error thrown when the deadline passes first.
 * @returns What the work resolved to.
 * @throws {Error} The error of the work, or one with `message` when the deadline passes first.
 */
export async function withDeadline<T>(
  work: () => Promise<T>,
  ms: number,
  message: string
): Promise<T> {
  let timer: NodeJS.Timeout | undefined
  const settled = new CapturedPromise<T>((resolve, reject) => {
    timer = setTimeout(() => {
      reject(new Error(message))
    }, ms)
    const run = async (): Promise<void> => {
      try {
        resolve(await work())
      } catch (error: unknown) {
        reject(error)
      }
    }
    void run()
  })
  try {
    return await settled
  } finally {
    clearTimeout(timer)
  }
}
