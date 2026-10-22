import { CompatibilityError } from "./errors.js";

/** Native fetch decompresses responses before SDK bounds can be applied. */
export function requirePatchedNodeFetch(version: string): void {
  const match = /^(\d+)\.(\d+)\.(\d+)$/u.exec(version);
  const [major, minor, patch] = match === null ? [] : match.slice(1).map(Number);
  if (major !== 24 || minor === undefined || patch === undefined
      || minor < 22 || (minor === 22 && patch < 1)) {
    throw new CompatibilityError("built-in fetch requires patched Node.js >=24.22.1 <25; upgrade Node and restart the process");
  }
}
