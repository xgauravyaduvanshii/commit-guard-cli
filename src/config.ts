/**
 * commit-guard.json — per-repo configuration for commit-guard-cli.
 *
 * The CLI looks for `commit-guard.json` in the directory it runs in (the
 * repo root when the pre-commit hook runs). `commit-guard init --config`
 * writes an example file. A `--config <path>` flag points at a different
 * file; `--no-config` ignores the file entirely.
 *
 * All fields are optional; anything missing falls back to the built-in
 * defaults. An invalid file is an error (exit 2) — silently ignoring a
 * broken config would let secrets through.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

export interface CustomPattern {
  id: string;
  name: string;
  description?: string;
  regex: string;
}

export interface EntropyConfig {
  enabled?: boolean;
  threshold?: number;
  minLength?: number;
}

export interface CommitGuardConfig {
  /** Extra secret patterns, added to the built-in ones. */
  patterns?: CustomPattern[];
  /** Large-file limit in megabytes (default 5). */
  maxSizeMb?: number;
  /** Extra allowlist entries (substrings, or /regex/). */
  allowlist?: string[];
  /**
   * Extra blocked files: a basename that must never be committed. An entry
   * matches a file when its basename equals the entry, or ends with it
   * (so ".keystore" blocks "release.keystore").
   */
  denyList?: string[];
  entropy?: EntropyConfig;
}

export const CONFIG_FILENAME = 'commit-guard.json';

/** The example file `init --config` writes. */
export function exampleConfig(): CommitGuardConfig {
  return {
    maxSizeMb: 5,
    allowlist: [],
    denyList: ['credentials.json', '.keystore'],
    patterns: [
      {
        id: 'my-api-key',
        name: 'Example custom pattern',
        description: 'Replace this with a pattern for your own service, e.g. MYAPI- + 32 letters/digits.',
        regex: '\\bMYAPI-[A-Za-z0-9]{32}\\b',
      },
    ],
    entropy: { enabled: true, threshold: 4.5, minLength: 20 },
  };
}

export function configPath(cwd: string): string {
  return path.join(cwd, CONFIG_FILENAME);
}

export type LoadConfigResult =
  | { ok: true; config: CommitGuardConfig; path: string | null }
  | { ok: false; error: string };

function validateConfig(raw: unknown): { config: CommitGuardConfig } | { error: string } {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    return { error: 'Config must be a JSON object.' };
  }
  const obj = raw as Record<string, unknown>;
  if (obj.maxSizeMb !== undefined && (typeof obj.maxSizeMb !== 'number' || !Number.isFinite(obj.maxSizeMb) || obj.maxSizeMb <= 0)) {
    return { error: 'Config "maxSizeMb" must be a positive number.' };
  }
  if (obj.allowlist !== undefined && (!Array.isArray(obj.allowlist) || obj.allowlist.some((e) => typeof e !== 'string'))) {
    return { error: 'Config "allowlist" must be an array of strings.' };
  }
  if (obj.denyList !== undefined && (!Array.isArray(obj.denyList) || obj.denyList.some((e) => typeof e !== 'string'))) {
    return { error: 'Config "denyList" must be an array of strings.' };
  }
  if (obj.patterns !== undefined) {
    if (!Array.isArray(obj.patterns)) return { error: 'Config "patterns" must be an array.' };
    for (const p of obj.patterns as Array<Record<string, unknown>>) {
      if (typeof p !== 'object' || p === null || typeof p.id !== 'string' || p.id === '' || typeof p.regex !== 'string' || p.regex === '') {
        return { error: 'Each config pattern needs a non-empty "id" and "regex" string.' };
      }
      if (typeof p.name !== 'string' || p.name === '') {
        return { error: `Config pattern "${p.id}" needs a non-empty "name".` };
      }
      try {
        new RegExp(p.regex as string);
      } catch {
        return { error: `Config pattern "${p.id}" has an invalid regex: ${p.regex as string}` };
      }
    }
  }
  if (obj.entropy !== undefined) {
    if (typeof obj.entropy !== 'object' || obj.entropy === null || Array.isArray(obj.entropy)) {
      return { error: 'Config "entropy" must be an object.' };
    }
    const e = obj.entropy as Record<string, unknown>;
    if (e.enabled !== undefined && typeof e.enabled !== 'boolean') {
      return { error: 'Config "entropy.enabled" must be a boolean.' };
    }
    if (e.threshold !== undefined && (typeof e.threshold !== 'number' || !Number.isFinite(e.threshold) || e.threshold <= 0)) {
      return { error: 'Config "entropy.threshold" must be a positive number.' };
    }
    if (e.minLength !== undefined && (typeof e.minLength !== 'number' || !Number.isFinite(e.minLength) || e.minLength < 1)) {
      return { error: 'Config "entropy.minLength" must be a positive number.' };
    }
  }
  return { config: obj as unknown as CommitGuardConfig };
}

/**
 * Load the config for a run. `explicitPath` is the `--config` value;
 * otherwise the file in `cwd` is used when present. No file means defaults.
 */
export function loadConfig(cwd: string, explicitPath?: string): LoadConfigResult {
  const file = explicitPath ?? configPath(cwd);
  if (!existsSync(file)) {
    if (explicitPath) return { ok: false, error: `Config file not found: ${explicitPath}` };
    return { ok: true, config: {}, path: null };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(file, 'utf8')) as unknown;
  } catch (err) {
    return { ok: false, error: `Config file is not valid JSON (${file}): ${err instanceof Error ? err.message : String(err)}` };
  }
  const validated = validateConfig(parsed);
  if ('error' in validated) return { ok: false, error: `Invalid config (${file}): ${validated.error}` };
  return { ok: true, config: validated.config, path: file };
}

export type ScaffoldResult =
  | { ok: true; path: string }
  | { ok: false; reason: string };

/** Write the example config. Refuses to overwrite an existing file unless `force` is set. */
export function scaffoldConfig(cwd: string, force = false): ScaffoldResult {
  const file = configPath(cwd);
  if (existsSync(file) && !force) {
    return { ok: false, reason: `commit-guard.json already exists. Use --force to overwrite it.` };
  }
  writeFileSync(file, `${JSON.stringify(exampleConfig(), null, 2)}\n`);
  return { ok: true, path: file };
}
