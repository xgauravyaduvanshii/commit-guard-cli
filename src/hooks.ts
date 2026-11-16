import { chmodSync, existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { gitDir } from './git.js';

export const HOOK_MARKER = '# commit-guard';
export const HOOK_FILENAME = 'pre-commit';

export function hookScript(): string {
  return `#!/bin/sh
${HOOK_MARKER} pre-commit hook — installed by commit-guard-cli.
# If commit-guard is not on PATH, the commit proceeds with a warning
# instead of failing (install it with: npm install -g commit-guard-cli).
if command -v commit-guard >/dev/null 2>&1; then
  exec commit-guard scan --staged
else
  echo "commit-guard: not found on PATH, skipping secret scan." >&2
  exit 0
fi
`;
}

export function hookPath(cwd: string): string | null {
  const dir = gitDir(cwd);
  return dir ? path.join(dir, 'hooks', HOOK_FILENAME) : null;
}

export function isOurHook(cwd: string): boolean {
  const p = hookPath(cwd);
  if (!p || !existsSync(p)) return false;
  return readFileSync(p, 'utf8').includes(HOOK_MARKER);
}

export type InstallResult =
  | { ok: true; path: string; backedUp: boolean }
  | { ok: false; reason: string };

/** Install the pre-commit hook. An existing non-commit-guard hook is backed up, never overwritten silently. */
export function installHook(cwd: string): InstallResult {
  const p = hookPath(cwd);
  if (!p) return { ok: false, reason: 'Not a git repository.' };
  let backedUp = false;
  if (existsSync(p) && !isOurHook(cwd)) {
    writeFileSync(`${p}.bak`, readFileSync(p));
    backedUp = true;
  }
  writeFileSync(p, hookScript());
  chmodSync(p, 0o755);
  return { ok: true, path: p, backedUp };
}

export type UninstallResult =
  | { ok: true; path: string; restoredBackup: boolean }
  | { ok: false; reason: string };

/** Remove our hook; restore a backed-up hook when one exists. */
export function uninstallHook(cwd: string): UninstallResult {
  const p = hookPath(cwd);
  if (!p) return { ok: false, reason: 'Not a git repository.' };
  if (!existsSync(p)) return { ok: false, reason: 'No pre-commit hook is installed.' };
  if (!isOurHook(cwd)) {
    return { ok: false, reason: 'The pre-commit hook was not installed by commit-guard; refusing to remove it.' };
  }
  const backup = `${p}.bak`;
  const restoredBackup = existsSync(backup);
  if (restoredBackup) {
    writeFileSync(p, readFileSync(backup));
    chmodSync(p, 0o755);
  } else {
    unlinkSync(p);
  }
  return { ok: true, path: p, restoredBackup };
}
