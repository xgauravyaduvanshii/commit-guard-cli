import { describe, expect, it } from 'vitest';
import { checkLargeFile, formatBytes, isBlockedFile, scanContents } from '../src/scan.js';

describe('blocked files', () => {
  it('blocks .env and .env.* but allows .env.example', () => {
    expect(isBlockedFile('.env')).toBe(true);
    expect(isBlockedFile('.env.local')).toBe(true);
    expect(isBlockedFile('config/.env.production')).toBe(true);
    expect(isBlockedFile('.env.example')).toBe(false);
    expect(isBlockedFile('.env.sample')).toBe(false);
    expect(isBlockedFile('app.js')).toBe(false);
  });

  it('blocks private-key files', () => {
    expect(isBlockedFile('key.pem')).toBe(true);
    expect(isBlockedFile('certs/server.key')).toBe(true);
    expect(isBlockedFile('id_rsa')).toBe(true);
    expect(isBlockedFile('cert.pem')).toBe(true);
    expect(isBlockedFile('notes.txt')).toBe(false);
  });
});

describe('large files', () => {
  it('flags files over the 5 MB default and marks >100 MB as a GitHub reject', () => {
    expect(checkLargeFile('a.bin', 4 * 1024 * 1024, 5 * 1024 * 1024)).toBeNull();
    const large = checkLargeFile('a.bin', 6 * 1024 * 1024, 5 * 1024 * 1024);
    expect(large?.exceedsGitHubLimit).toBe(false);
    const huge = checkLargeFile('a.bin', 101 * 1024 * 1024, 5 * 1024 * 1024);
    expect(huge?.exceedsGitHubLimit).toBe(true);
  });

  it('formats byte sizes', () => {
    expect(formatBytes(500)).toBe('500 B');
    expect(formatBytes(2048)).toBe('2.0 KB');
    expect(formatBytes(6 * 1024 * 1024)).toBe('6.0 MB');
  });
});

describe('scanContents', () => {
  it('blocks a file containing a secret and reports file + line', () => {
    const result = scanContents([
      { path: 'config.js', content: 'const k = "AKIA1234567890ABCDEF";', bytes: 40 },
    ]);
    expect(result.blocked).toBe(true);
    expect(result.findings[0]?.file).toBe('config.js');
    expect(result.findings[0]?.patternId).toBe('aws-access-key');
  });

  it('passes clean contents', () => {
    const result = scanContents([
      { path: 'app.js', content: 'console.log("hello");', bytes: 22 },
    ]);
    expect(result.blocked).toBe(false);
    expect(result.findings).toEqual([]);
  });

  it('blocks a staged .env even with clean contents, and flags oversized files', () => {
    const result = scanContents([
      { path: '.env', content: 'FOO=bar', bytes: 7 },
      { path: 'big.bin', content: null, bytes: 6 * 1024 * 1024 },
    ]);
    expect(result.blocked).toBe(true);
    expect(result.blockedFiles).toEqual(['.env']);
    expect(result.largeFiles.map((f) => f.file)).toEqual(['big.bin']);
  });

  it('respects the allowlist and a custom size limit', () => {
    const secret = `AKIA${'1'.repeat(16)}`;
    const allowed = scanContents(
      [{ path: 'a.js', content: `key="${secret}"`, bytes: 30 }],
      { allowlist: [secret] },
    );
    expect(allowed.blocked).toBe(false);
    const sized = scanContents(
      [{ path: 'big.bin', content: null, bytes: 6 * 1024 * 1024 }],
      { maxFileBytes: 10 * 1024 * 1024 },
    );
    expect(sized.blocked).toBe(false);
  });
});
