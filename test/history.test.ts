import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { getCommitFileContent, getCommitFiles, getRecentCommits, scanHistory } from '../src/history.js';

function git(cwd: string, ...args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8' });
}

function commit(cwd: string, file: string, content: string, message: string): void {
  writeFileSync(path.join(cwd, file), content);
  git(cwd, 'add', file);
  git(cwd, 'commit', '-qm', message);
}

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'commit-guard-history-'));
  git(dir, 'init', '-q');
  git(dir, 'config', 'user.email', 'test@example.com');
  git(dir, 'config', 'user.name', 'Test');
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('history helpers in a real temp repo', () => {
  it('lists recent commits newest first, with subjects', () => {
    commit(dir, 'a.txt', 'one\n', 'first commit');
    commit(dir, 'b.txt', 'two\n', 'second commit');
    const commits = getRecentCommits(dir, 2);
    expect(commits).toHaveLength(2);
    expect(commits[0]?.subject).toBe('second commit');
    expect(commits[1]?.subject).toBe('first commit');
    expect(commits[0]?.sha).toMatch(/^[0-9a-f]{40}$/);
    expect(getRecentCommits(dir, 1)).toHaveLength(1);
  });

  it('returns no commits for a repo with no history', () => {
    expect(getRecentCommits(dir, 5)).toEqual([]);
    expect(scanHistory(dir, 5).findings).toEqual([]);
  });

  it('lists files and content of a commit', () => {
    commit(dir, 'app.js', 'console.log("hi");\n', 'add app');
    const [head] = getRecentCommits(dir, 1);
    expect(head).toBeDefined();
    expect(getCommitFiles(dir, head?.sha ?? '')).toEqual(['app.js']);
    expect(getCommitFileContent(dir, head?.sha ?? '', 'app.js')).toContain('console.log');
    expect(getCommitFileContent(dir, head?.sha ?? '', 'missing.js')).toBeNull();
  });
});

describe('scanHistory', () => {
  it('finds a secret committed in the last n commits, with SHA and subject', () => {
    commit(dir, 'clean.js', 'console.log("hi");\n', 'clean start');
    commit(dir, 'config.js', 'const k = "AKIA1234567890ABCDEF";\n', 'add config with key');
    const result = scanHistory(dir, 2);
    expect(result.commits).toHaveLength(2);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.patternId).toBe('aws-access-key');
    expect(result.findings[0]?.file).toBe('config.js');
    expect(result.findings[0]?.subject).toBe('add config with key');
    expect(result.findings[0]?.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(result.findings[0]?.snippet).not.toContain('AKIA1234567890ABCDEF');
  });

  it('only scans the requested number of commits', () => {
    commit(dir, 'config.js', 'const k = "AKIA1234567890ABCDEF";\n', 'old secret commit');
    commit(dir, 'clean.js', 'console.log("hi");\n', 'clean follow-up');
    // Latest commit only: the secret is one commit back.
    expect(scanHistory(dir, 1).findings).toEqual([]);
    expect(scanHistory(dir, 2).findings).toHaveLength(1);
  });

  it('finds nothing in clean history', () => {
    commit(dir, 'a.js', 'console.log("a");\n', 'clean one');
    commit(dir, 'b.js', 'console.log("b");\n', 'clean two');
    const result = scanHistory(dir, 2);
    expect(result.findings).toEqual([]);
    expect(result.blockedFiles).toEqual([]);
    expect(result.scannedFiles).toBe(2);
  });

  it('reports a .env file committed in history as a blocked file', () => {
    commit(dir, '.env', 'FOO=bar\n', 'accidentally commit env');
    const result = scanHistory(dir, 1);
    expect(result.blockedFiles).toHaveLength(1);
    expect(result.blockedFiles[0]?.file).toBe('.env');
    expect(result.blockedFiles[0]?.subject).toBe('accidentally commit env');
  });

  it('finds a high-entropy token committed in history', () => {
    commit(dir, 'token.js', 'const t = "xK9mQ2vL8pR4tY7wN3sD6fH1jK5";\n', 'add token');
    const result = scanHistory(dir, 1);
    expect(result.findings.map((f) => f.patternId)).toContain('high-entropy-string');
  });
});
