import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  getStagedContent,
  getStagedFiles,
  getTrackedIgnoredFiles,
  isGitRepo,
  untrackCommand,
} from '../src/git.js';
import { installHook, isOurHook, uninstallHook } from '../src/hooks.js';

function git(cwd: string, ...args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8' });
}

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'commit-guard-git-'));
  git(dir, 'init', '-q');
  git(dir, 'config', 'user.email', 'test@example.com');
  git(dir, 'config', 'user.name', 'Test');
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('git helpers in a real temp repo', () => {
  it('detects a git repo and lists staged files with staged content', () => {
    expect(isGitRepo(dir)).toBe(true);
    writeFileSync(path.join(dir, 'app.js'), 'const k = "AKIA1234567890ABCDEF";\n');
    writeFileSync(path.join(dir, 'clean.js'), 'console.log("hi");\n');
    git(dir, 'add', 'app.js', 'clean.js');
    expect(getStagedFiles(dir).sort()).toEqual(['app.js', 'clean.js']);
    expect(getStagedContent(dir, 'app.js')).toContain('AKIA1234567890ABCDEF');
    expect(getStagedContent(dir, 'missing.js')).toBeNull();
  });

  it('finds tracked-but-ignored files and gives the exact untrack command', () => {
    writeFileSync(path.join(dir, '.gitignore'), 'secret.txt\n');
    writeFileSync(path.join(dir, 'secret.txt'), 'do not commit me\n');
    git(dir, 'add', '-f', 'secret.txt', '.gitignore');
    git(dir, 'commit', '-qm', 'track secret before ignore');
    expect(getTrackedIgnoredFiles(dir)).toEqual(['secret.txt']);
    expect(untrackCommand('secret.txt')).toBe('git rm -r --cached "secret.txt"');
  });

  it('installs and uninstalls the pre-commit hook, backing up an existing hook', () => {
    writeFileSync(path.join(dir, '.git', 'hooks', 'pre-commit'), '#!/bin/sh\necho old\n');
    const installed = installHook(dir);
    expect(installed.ok).toBe(true);
    if (installed.ok) expect(installed.backedUp).toBe(true);
    expect(isOurHook(dir)).toBe(true);
    const uninstalled = uninstallHook(dir);
    expect(uninstalled.ok).toBe(true);
    if (uninstalled.ok) expect(uninstalled.restoredBackup).toBe(true);
    expect(isOurHook(dir)).toBe(false);
  });

  it('refuses to uninstall a hook it did not install', () => {
    writeFileSync(path.join(dir, '.git', 'hooks', 'pre-commit'), '#!/bin/sh\necho someone-elses-hook\n');
    const r = uninstallHook(dir);
    expect(r.ok).toBe(false);
  });
});
