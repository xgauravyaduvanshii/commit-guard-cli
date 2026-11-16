import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { exampleConfig, loadConfig, scaffoldConfig } from '../src/config.js';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'commit-guard-config-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function writeConfig(content: string): void {
  writeFileSync(path.join(dir, 'commit-guard.json'), content);
}

describe('loadConfig', () => {
  it('returns defaults when no config file exists', () => {
    const r = loadConfig(dir);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.config).toEqual({});
      expect(r.path).toBeNull();
    }
  });

  it('loads a valid config file', () => {
    writeConfig(JSON.stringify({
      maxSizeMb: 10,
      allowlist: ['SAFE-VALUE'],
      denyList: ['credentials.json'],
      patterns: [{ id: 'x-key', name: 'X key', regex: '\\bXKEY-[0-9]+\\b' }],
      entropy: { threshold: 5, minLength: 24 },
    }));
    const r = loadConfig(dir);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.config.maxSizeMb).toBe(10);
      expect(r.config.allowlist).toEqual(['SAFE-VALUE']);
      expect(r.config.denyList).toEqual(['credentials.json']);
      expect(r.config.patterns?.[0]?.id).toBe('x-key');
      expect(r.config.entropy?.threshold).toBe(5);
    }
  });

  it('rejects invalid JSON', () => {
    writeConfig('{ not json');
    const r = loadConfig(dir);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/not valid JSON/);
  });

  it('rejects a non-object config', () => {
    writeConfig('["a", "b"]');
    const r = loadConfig(dir);
    expect(r.ok).toBe(false);
  });

  it('rejects an invalid pattern regex, naming the pattern', () => {
    writeConfig(JSON.stringify({ patterns: [{ id: 'bad-one', name: 'Bad', regex: '([unclosed' }] }));
    const r = loadConfig(dir);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('bad-one');
  });

  it('rejects a pattern without an id or name', () => {
    writeConfig(JSON.stringify({ patterns: [{ regex: 'abc' }] }));
    expect(loadConfig(dir).ok).toBe(false);
    writeConfig(JSON.stringify({ patterns: [{ id: 'x', regex: 'abc' }] }));
    expect(loadConfig(dir).ok).toBe(false);
  });

  it('rejects a non-positive maxSizeMb and a non-array allowlist', () => {
    writeConfig(JSON.stringify({ maxSizeMb: 0 }));
    expect(loadConfig(dir).ok).toBe(false);
    writeConfig(JSON.stringify({ allowlist: 'not-an-array' }));
    expect(loadConfig(dir).ok).toBe(false);
    writeConfig(JSON.stringify({ entropy: { threshold: 'high' } }));
    expect(loadConfig(dir).ok).toBe(false);
  });

  it('errors on an explicit --config path that does not exist', () => {
    const r = loadConfig(dir, path.join(dir, 'missing.json'));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/not found/);
  });
});

describe('scaffoldConfig', () => {
  it('writes a valid example config', () => {
    const r = scaffoldConfig(dir);
    expect(r.ok).toBe(true);
    const file = path.join(dir, 'commit-guard.json');
    expect(existsSync(file)).toBe(true);
    const loaded = loadConfig(dir);
    expect(loaded.ok).toBe(true);
    if (loaded.ok) {
      expect(loaded.config.maxSizeMb).toBe(5);
      expect(loaded.config.entropy?.enabled).toBe(true);
    }
    expect(() => JSON.parse(readFileSync(file, 'utf8'))).not.toThrow();
  });

  it('refuses to overwrite without --force, and overwrites with it', () => {
    scaffoldConfig(dir);
    expect(scaffoldConfig(dir).ok).toBe(false);
    const r = scaffoldConfig(dir, true);
    expect(r.ok).toBe(true);
  });
});

describe('exampleConfig', () => {
  it('is itself a valid config', () => {
    writeConfig(JSON.stringify(exampleConfig()));
    expect(loadConfig(dir).ok).toBe(true);
  });
});
