import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';

/** Run git in `cwd` and return trimmed stdout. Throws on non-zero exit. */
export function runGit(args: string[], cwd: string): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

/** Run git, returning null instead of throwing (for optional probes). */
export function tryGit(args: string[], cwd: string): string | null {
  try {
    return runGit(args, cwd);
  } catch {
    return null;
  }
}

export function isGitRepo(cwd: string): boolean {
  return tryGit(['rev-parse', '--git-dir'], cwd) !== null;
}

export function gitDir(cwd: string): string | null {
  const out = tryGit(['rev-parse', '--absolute-git-dir'], cwd);
  return out ?? (existsSync(path.join(cwd, '.git')) ? path.join(cwd, '.git') : null);
}

/** Files currently staged (in the index), relative to the repo root. */
export function getStagedFiles(cwd: string): string[] {
  const out = tryGit(['diff', '--cached', '--name-only', '-z'], cwd);
  if (out === null || out === '') return [];
  return out.split('\0').filter((f) => f !== '');
}

/**
 * Staged content of one file (`git show :path`), or null when the file was
 * deleted from the index / is unreadable. Binary blobs return null.
 */
export function getStagedContent(cwd: string, file: string): string | null {
  try {
    const buf = execFileSync('git', ['show', `:${file}`], {
      cwd,
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 100 * 1024 * 1024,
    }) as Buffer;
    if (buf.includes(0)) return null; // binary
    return buf.toString('utf8');
  } catch {
    return null;
  }
}

/** Byte size of the staged blob, or null when unavailable. */
export function getStagedSize(cwd: string, file: string): number | null {
  const out = tryGit(['cat-file', '-s', `:${file}`], cwd);
  if (out === null) return null;
  const n = Number.parseInt(out, 10);
  return Number.isFinite(n) ? n : null;
}

/**
 * Tracked files that match an ignore rule — the classic "committed .env
 * before .gitignore existed" mistake. `git ls-files -i --cached
 * --exclude-standard` lists exactly those.
 */
export function getTrackedIgnoredFiles(cwd: string): string[] {
  const out = tryGit(['ls-files', '-i', '--cached', '--exclude-standard', '-z'], cwd);
  if (out === null || out === '') return [];
  return out.split('\0').filter((f) => f !== '');
}

export function hasRemote(cwd: string): boolean {
  const out = tryGit(['remote'], cwd);
  return out !== null && out !== '';
}

export function hasCommits(cwd: string): boolean {
  return tryGit(['rev-parse', 'HEAD'], cwd) !== null;
}

/**
 * True when the current HEAD has an upstream branch — a rough signal that
 * history may already be shared, so a found secret needs rotating first.
 * This is a hint, not proof: a secret can be pushed without an upstream.
 */
export function hasUpstream(cwd: string): boolean {
  return tryGit(['rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{u}'], cwd) !== null;
}

/** Exact fix command for a tracked-but-ignored file (no shell quoting games). */
export function untrackCommand(file: string): string {
  return `git rm -r --cached ${JSON.stringify(file)}`;
}
