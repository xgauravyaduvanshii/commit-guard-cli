/**
 * `scan --history <n>` — look for secrets that were already committed.
 *
 * The staged scan can only stop a secret before it lands. This scan looks
 * back at the last `n` commits and reports any secret-shaped content in
 * them, with the commit SHA and subject, so the secret can be rotated.
 * A secret found here is already in history: un-staging does nothing,
 * the rotate-first guidance always applies.
 */
import { execFileSync } from 'node:child_process';
import { runGit, tryGit } from './git.js';
import { scanContents, type FileFinding } from './scan.js';
import type { ScanContentOptions } from './scan.js';

export interface HistoryCommit {
  sha: string;
  subject: string;
}

export interface HistoryFinding extends FileFinding {
  commit: string;
  subject: string;
}

export interface HistoryBlockedFile {
  commit: string;
  subject: string;
  file: string;
}

export interface HistoryResult {
  commits: HistoryCommit[];
  findings: HistoryFinding[];
  blockedFiles: HistoryBlockedFile[];
  scannedFiles: number;
}

/** The last `n` commits, newest first. Empty when the repo has no commits. */
export function getRecentCommits(cwd: string, count: number): HistoryCommit[] {
  const out = tryGit(['log', `-n${count}`, '--format=%H %s'], cwd);
  if (out === null || out === '') return [];
  return out
    .split('\n')
    .filter((line) => line.length >= 40)
    .map((line) => ({ sha: line.slice(0, 40), subject: line.slice(41) }));
}

/** Files changed in one commit (root commit included), NUL-separated. */
export function getCommitFiles(cwd: string, sha: string): string[] {
  const out = tryGit(['diff-tree', '--no-commit-id', '--name-only', '-r', '--root', '-z', sha], cwd);
  if (out === null || out === '') return [];
  return out.split('\0').filter((f) => f !== '');
}

/** Content of a file at a commit, or null for binary / deleted / unreadable files. */
export function getCommitFileContent(cwd: string, sha: string, file: string): string | null {
  try {
    const buf = execFileSync('git', ['show', `${sha}:${file}`], {
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

/** Byte size of a file at a commit, or 0 when unavailable. */
export function getCommitFileSize(cwd: string, sha: string, file: string): number {
  const out = tryGit(['cat-file', '-s', `${sha}:${file}`], cwd);
  if (out === null) return 0;
  const n = Number.parseInt(out, 10);
  return Number.isFinite(n) ? n : 0;
}

export function scanHistory(
  cwd: string,
  count: number,
  options: ScanContentOptions = {},
): HistoryResult {
  const commits = getRecentCommits(cwd, count);
  const findings: HistoryFinding[] = [];
  const blockedFiles: HistoryBlockedFile[] = [];
  let scannedFiles = 0;
  for (const commit of commits) {
    const files = getCommitFiles(cwd, commit.sha).map((file) => ({
      path: file,
      content: getCommitFileContent(cwd, commit.sha, file),
      bytes: getCommitFileSize(cwd, commit.sha, file),
    }));
    scannedFiles += files.length;
    const result = scanContents(files, options);
    for (const f of result.findings) {
      findings.push({ ...f, commit: commit.sha, subject: commit.subject });
    }
    for (const file of result.blockedFiles) {
      blockedFiles.push({ commit: commit.sha, subject: commit.subject, file });
    }
  }
  return { commits, findings, blockedFiles, scannedFiles };
}

/** Re-exported for callers that only need the git plumbing. */
export { runGit };
