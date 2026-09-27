/** Shared helpers for the unit tests (kept separate so the suite reads cleanly). */
import { validateIoc } from '../core/ioc/validate.js';
import { emptyVerdict } from '../providers/types.js';
import type { NormalizedIoc } from '../core/types.js';

/** Parse a value through the real validator so tests use the production path. */
export function normalizeIocForTest(value: string, type: NormalizedIoc['type']): NormalizedIoc {
  const result = validateIoc(value);
  if (!result.ok) {
    // Allow tests to exercise values the validator rejects by building the shape
    // directly; the assertions under test do not depend on validation.
    return { value, raw: value, type, parsed: {} };
  }
  assertType(result.ioc.type, type);
  return result.ioc;
}

function assertType(actual: string, expected: string): void {
  if (actual !== expected) {
    throw new Error(`expected detection type ${expected} but got ${actual}`);
  }
}

export { emptyVerdict };
