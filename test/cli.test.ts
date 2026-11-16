import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { main } from '../src/cli.js';

function git(cwd: string, ...args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8' });
}

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'commit-guard-cli-'));
  git(dir, 'init', '-q');
  git(dir, 'config', 'user.email', 'test@example.com');
  git(dir, 'config', 'user.name', 'Test');
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function commit(cwd: string, file: string, content: string, message: string): void {
  writeFileSync(path.join(cwd, file), content);
  git(cwd, 'add', file);
  git(cwd, 'commit', '-qm', message);
}

describe('cli: init --config', () => {
  it('writes an example commit-guard.json', () => {
    expect(main(['init', '--config'], dir)).toBe(0);
    const file = path.join(dir, 'commit-guard.json');
    expect(existsSync(file)).toBe(true);
    expect(() => JSON.parse(readFileSync(file, 'utf8'))).not.toThrow();
    expect(JSON.parse(readFileSync(file, 'utf8')).entropy.enabled).toBe(true);
  });

  it('refuses to overwrite without --force, and overwrites with it', () => {
    expect(main(['init', '--config'], dir)).toBe(0);
    expect(main(['init', '--config'], dir)).toBe(2);
    expect(main(['init', '--config', '--force'], dir)).toBe(0);
  });
});

describe('cli: scan --history', () => {
  it('exits 1 when a secret is in the scanned history, 0 when clean', () => {
    commit(dir, 'config.js', 'const k = "AKIA1234567890ABCDEF";\n', 'add key');
    expect(main(['scan', '--history', '1'], dir)).toBe(1);
    expect(main(['scan', '--history', '1', '--json'], dir)).toBe(1);
    expect(main(['scan', '--history', '1', '--quiet'], dir)).toBe(1);
  });

  it('exits 0 for clean history', () => {
    commit(dir, 'app.js', 'console.log("hi");\n', 'clean');
    expect(main(['scan', '--history', '1'], dir)).toBe(0);
  });

  it('rejects invalid history counts', () => {
    expect(main(['scan', '--history', '0'], dir)).toBe(2);
    expect(main(['scan', '--history', '101'], dir)).toBe(2);
    expect(main(['scan', '--history', 'abc'], dir)).toBe(2);
  });
});

describe('cli: config file in scan --staged', () => {
  it('applies a custom pattern from commit-guard.json', () => {
    writeFileSync(
      path.join(dir, 'commit-guard.json'),
      JSON.stringify({
        patterns: [{ id: 'my-api-key', name: 'My API key', regex: '\\bMYAPI-[A-Za-z0-9]{32}\\b' }],
      }),
    );
    writeFileSync(path.join(dir, 'app.js'), `const k = "MYAPI-${'a'.repeat(32)}";\n`);
    git(dir, 'add', 'app.js', 'commit-guard.json');
    expect(main(['scan', '--staged'], dir)).toBe(1);
  });

  it('ignores the config with --no-config', () => {
    writeFileSync(
      path.join(dir, 'commit-guard.json'),
      JSON.stringify({
        patterns: [{ id: 'my-api-key', name: 'My API key', regex: '\\bMYAPI-[A-Za-z0-9]{32}\\b' }],
      }),
    );
    writeFileSync(path.join(dir, 'app.js'), `const k = "MYAPI-${'a'.repeat(32)}";\n`);
    git(dir, 'add', 'app.js', 'commit-guard.json');
    expect(main(['scan', '--staged', '--no-config'], dir)).toBe(0);
  });

  it('applies denyList and maxSizeMb from the config', () => {
    writeFileSync(
      path.join(dir, 'commit-guard.json'),
      JSON.stringify({ denyList: ['credentials.json'], maxSizeMb: 1 }),
    );
    writeFileSync(path.join(dir, 'credentials.json'), '{}\n');
    git(dir, 'add', 'credentials.json', 'commit-guard.json');
    expect(main(['scan', '--staged'], dir)).toBe(1);
  });

  it('errors on an invalid config file instead of scanning', () => {
    writeFileSync(path.join(dir, 'commit-guard.json'), '{ broken json');
    writeFileSync(path.join(dir, 'app.js'), 'console.log("hi");\n');
    git(dir, 'add', 'app.js', 'commit-guard.json');
    expect(main(['scan', '--staged'], dir)).toBe(2);
  });

  it('errors on a missing --config file', () => {
    writeFileSync(path.join(dir, 'app.js'), 'console.log("hi");\n');
    git(dir, 'add', 'app.js');
    expect(main(['scan', '--staged', '--config', 'nope.json'], dir)).toBe(2);
  });
});

describe('cli: entropy in scan --staged', () => {
  it('blocks a staged high-entropy token', () => {
    writeFileSync(path.join(dir, 'token.js'), 'const t = "xK9mQ2vL8pR4tY7wN3sD6fH1jK5";\n');
    git(dir, 'add', 'token.js');
    expect(main(['scan', '--staged'], dir)).toBe(1);
  });
});
