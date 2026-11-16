#!/usr/bin/env node
/**
 * commit-guard — zero-dependency pre-commit guard.
 *
 *   commit-guard scan --staged [--json] [--quiet] [--max-size-mb N] [--allowlist FILE] [--config FILE]
 *   commit-guard scan <path...>          scan files / directories on disk
 *   commit-guard scan --history <n>      scan the last n commits for secrets already committed
 *   commit-guard init --config [--force] write an example commit-guard.json
 *   commit-guard install                 install .git/hooks/pre-commit
 *   commit-guard uninstall               remove it (restores a backed-up hook)
 *
 * Exit codes: 0 = pass (warnings allowed), 1 = blocked, 2 = usage / environment error.
 * Scan output never contains a secret value — findings are redacted at the
 * pattern layer (see src/patterns.ts) and entropy findings report only a
 * token's length and entropy, never the token.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { loadConfig, scaffoldConfig, type CommitGuardConfig } from './config.js';
import { getStagedContent, getStagedFiles, getStagedSize, getTrackedIgnoredFiles, hasCommits, hasUpstream, isGitRepo, untrackCommand } from './git.js';
import { scanHistory, type HistoryResult } from './history.js';
import { installHook, uninstallHook } from './hooks.js';
import { DEFAULT_PATTERNS, parseAllowlistFile, type SecretPattern } from './patterns.js';
import { DEFAULT_MAX_FILE_BYTES, formatBytes, scanContents, type ScanResult } from './scan.js';

export const VERSION = '0.2.0';

const ROTATE_GUIDANCE = [
  'If this secret was already pushed (or may have been), removing it from',
  'staging is NOT enough — it stays in git history and on the remote.',
  'Rotate it FIRST, then clean history:',
  '  1. Revoke / rotate the secret at the provider (AWS / GitHub / Stripe / OpenAI).',
  '  2. Remove it from history, e.g. `git filter-repo --invert-paths` or BFG.',
  '  3. Force-push only if your team agrees — history rewrites affect everyone.',
].join('\n');

function usage(): string {
  return [
    'commit-guard — block staged secrets, .env / private-key files and oversized files.',
    '',
    'Usage:',
    '  commit-guard scan --staged [--json] [--quiet] [--max-size-mb N] [--allowlist FILE] [--config FILE]',
    '  commit-guard scan <path...> [--json] [--quiet] [--max-size-mb N] [--allowlist FILE]',
    '  commit-guard scan --history <n> [--json] [--quiet]   scan the last n commits',
    '  commit-guard init --config [--force]                  write an example commit-guard.json',
    '  commit-guard install',
    '  commit-guard uninstall',
    '  commit-guard --help | --version',
    '',
    'Exit codes: 0 pass, 1 blocked, 2 usage / environment error.',
    'Default large-file limit: 5 MB (GitHub rejects files over 100 MB).',
    'Config: commit-guard.json in the repo root (custom patterns, maxSizeMb,',
    'allowlist, denyList, entropy). --config points at another file,',
    '--no-config ignores it.',
  ].join('\n');
}

interface ScanOptions {
  staged: boolean;
  paths: string[];
  json: boolean;
  quiet: boolean;
  maxFileBytes: number | null; // null = take from config / default
  allowlist: string[];
  history: number | null;
  configPath: string | undefined;
  noConfig: boolean;
}

/** Compile config patterns (regex strings) into SecretPatterns. Throws on a bad regex. */
export function compileCustomPatterns(config: CommitGuardConfig): SecretPattern[] {
  const out: SecretPattern[] = [...DEFAULT_PATTERNS];
  for (const p of config.patterns ?? []) {
    out.push({
      id: p.id,
      name: p.name,
      description: p.description ?? '',
      regex: new RegExp(p.regex, 'g'),
    });
  }
  return out;
}

export interface ResolvedScanSettings {
  maxFileBytes: number;
  allowlist: string[];
  patterns: SecretPattern[];
  denyList: string[];
  entropy: { enabled?: boolean; threshold?: number; minLength?: number };
}

/** Merge CLI flags over the config file over the built-in defaults. */
export function resolveScanSettings(config: CommitGuardConfig, opts: ScanOptions): ResolvedScanSettings {
  return {
    maxFileBytes:
      opts.maxFileBytes ??
      (config.maxSizeMb !== undefined ? Math.floor(config.maxSizeMb * 1024 * 1024) : DEFAULT_MAX_FILE_BYTES),
    allowlist: [...(config.allowlist ?? []), ...opts.allowlist],
    patterns: compileCustomPatterns(config),
    denyList: config.denyList ?? [],
    entropy: config.entropy ?? {},
  };
}

function parseScanArgs(args: string[]): ScanOptions | { error: string } {
  const opts: ScanOptions = {
    staged: false,
    paths: [],
    json: false,
    quiet: false,
    maxFileBytes: null,
    allowlist: [],
    history: null,
    configPath: undefined,
    noConfig: false,
  };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--staged') opts.staged = true;
    else if (arg === '--json') opts.json = true;
    else if (arg === '--quiet') opts.quiet = true;
    else if (arg === '--no-config') opts.noConfig = true;
    else if (arg === '--max-size-mb') {
      const v = Number(args[++i]);
      if (!Number.isFinite(v) || v <= 0) return { error: '--max-size-mb needs a positive number.' };
      opts.maxFileBytes = Math.floor(v * 1024 * 1024);
    } else if (arg.startsWith('--max-size-mb=')) {
      const v = Number(arg.slice('--max-size-mb='.length));
      if (!Number.isFinite(v) || v <= 0) return { error: '--max-size-mb needs a positive number.' };
      opts.maxFileBytes = Math.floor(v * 1024 * 1024);
    } else if (arg === '--allowlist') {
      const file = args[++i];
      if (!file || !existsSync(file)) return { error: `--allowlist file not found: ${file ?? ''}` };
      opts.allowlist = parseAllowlistFile(readFileSync(file, 'utf8'));
    } else if (arg.startsWith('--allowlist=')) {
      const file = arg.slice('--allowlist='.length);
      if (!existsSync(file)) return { error: `--allowlist file not found: ${file}` };
      opts.allowlist = parseAllowlistFile(readFileSync(file, 'utf8'));
    } else if (arg === '--config') {
      const file = args[++i];
      if (!file) return { error: '--config needs a file path.' };
      opts.configPath = file;
    } else if (arg.startsWith('--config=')) {
      opts.configPath = arg.slice('--config='.length);
    } else if (arg === '--history') {
      const v = Number(args[++i]);
      if (!Number.isInteger(v) || v < 1 || v > 100) return { error: '--history needs an integer from 1 to 100.' };
      opts.history = v;
    } else if (arg.startsWith('--history=')) {
      const v = Number(arg.slice('--history='.length));
      if (!Number.isInteger(v) || v < 1 || v > 100) return { error: '--history needs an integer from 1 to 100.' };
      opts.history = v;
    } else if (arg.startsWith('-')) {
      return { error: `Unknown option: ${arg}` };
    } else {
      opts.paths.push(arg);
    }
  }
  return opts;
}

function collectDiskFiles(paths: string[]): Array<{ path: string; content: string | null; bytes: number }> {
  const out: Array<{ path: string; content: string | null; bytes: number }> = [];
  const walk = (p: string) => {
    const st = statSync(p);
    if (st.isDirectory()) {
      for (const entry of readDir(p)) walk(path.join(p, entry));
    } else if (st.isFile()) {
      const buf = readFileSync(p);
      out.push({ path: p, content: buf.includes(0) ? null : buf.toString('utf8'), bytes: st.size });
    }
  };
  for (const p of paths) walk(p);
  return out;
}

function readDir(dir: string): string[] {
  return readdirSync(dir).filter((e) => e !== 'node_modules' && e !== '.git' && e !== 'dist');
}

function printHuman(result: ScanResult, cwd: string, opts: ScanOptions): void {
  if (opts.quiet) return;
  if (result.findings.length > 0) {
    console.log(`commit-guard: ${result.findings.length} secret-shaped finding(s):`);
    for (const f of result.findings) {
      console.log(`  ${f.file}:${f.line}  [${f.patternId}] ${f.patternName}`);
      if (f.snippet) console.log(`    ${f.snippet}`);
    }
  }
  for (const f of result.blockedFiles) {
    console.log(`commit-guard: blocked file staged: ${f} (never commit .env / private keys)`);
  }
  for (const f of result.largeFiles) {
    const note = f.exceedsGitHubLimit ? ' — GitHub rejects files over 100 MB' : '';
    console.log(`commit-guard: large file: ${f.file} (${formatBytes(f.bytes)})${note}`);
  }
  for (const f of result.trackedIgnored) {
    console.log(`commit-guard: warning: tracked but ignored: ${f}`);
    console.log(`  fix: ${untrackCommand(f)}  (then commit the removal)`);
  }
  if (result.blocked) {
    console.log('');
    console.log('commit-guard: BLOCKED — fix the items above, then stage again.');
    if (hasCommits(cwd) && hasUpstream(cwd)) {
      console.log(ROTATE_GUIDANCE);
    } else {
      console.log('Note: if this secret was ever pushed, rotate it first — un-staging does not erase history.');
    }
  } else if (result.trackedIgnored.length > 0) {
    console.log('commit-guard: passed with warnings.');
  } else {
    console.log('commit-guard: clean — no secrets, blocked files or oversized files found.');
  }
}

function printHistoryHuman(result: HistoryResult, opts: ScanOptions): void {
  if (opts.quiet) return;
  const blocked = result.findings.length > 0 || result.blockedFiles.length > 0;
  console.log(`commit-guard: scanned ${result.commits.length} commit(s), ${result.scannedFiles} file(s).`);
  if (result.findings.length > 0) {
    console.log(`commit-guard: ${result.findings.length} secret-shaped finding(s) already in history:`);
    for (const f of result.findings) {
      console.log(`  ${f.commit.slice(0, 7)} ${f.subject}`);
      console.log(`    ${f.file}:${f.line}  [${f.patternId}] ${f.patternName}`);
      if (f.snippet) console.log(`      ${f.snippet}`);
    }
  }
  for (const f of result.blockedFiles) {
    console.log(`commit-guard: blocked file in history: ${f.commit.slice(0, 7)} ${f.subject} — ${f.file}`);
  }
  if (blocked) {
    console.log('');
    console.log('commit-guard: BLOCKED — these secrets are already committed.');
    console.log(ROTATE_GUIDANCE);
  } else {
    console.log('commit-guard: clean — no secrets found in the scanned history.');
  }
}

export function runScan(
  cwd: string,
  opts: ScanOptions,
): { result: ScanResult | HistoryResult; code: number; isHistory: boolean } {
  const empty: ScanResult = { findings: [], blockedFiles: [], largeFiles: [], trackedIgnored: [], blocked: false };
  // Config: --config wins, --no-config skips the file, otherwise the file
  // in the working directory is used when present.
  let config: CommitGuardConfig = {};
  if (!opts.noConfig) {
    const loaded = loadConfig(cwd, opts.configPath);
    if (!loaded.ok) {
      console.error(`commit-guard: ${loaded.error}`);
      return { result: empty, code: 2, isHistory: false };
    }
    config = loaded.config;
  }
  let settings: ResolvedScanSettings;
  try {
    settings = resolveScanSettings(config, opts);
  } catch (err) {
    console.error(`commit-guard: bad config pattern: ${err instanceof Error ? err.message : String(err)}`);
    return { result: empty, code: 2, isHistory: false };
  }
  const scanOpts = {
    allowlist: settings.allowlist,
    maxFileBytes: settings.maxFileBytes,
    patterns: settings.patterns,
    denyList: settings.denyList,
    entropy: settings.entropy,
  };

  if (opts.history !== null) {
    if (!isGitRepo(cwd)) {
      console.error('commit-guard: --history needs a git repository.');
      return { result: empty, code: 2, isHistory: true };
    }
    const result = scanHistory(cwd, opts.history, scanOpts);
    return {
      result,
      code: result.findings.length > 0 || result.blockedFiles.length > 0 ? 1 : 0,
      isHistory: true,
    };
  }

  let files: Array<{ path: string; content: string | null; bytes: number }>;
  if (opts.staged) {
    if (!isGitRepo(cwd)) {
      console.error('commit-guard: --staged needs a git repository.');
      return { result: empty, code: 2, isHistory: false };
    }
    const staged = getStagedFiles(cwd);
    files = staged.map((f) => ({
      path: f,
      content: getStagedContent(cwd, f),
      bytes: getStagedSize(cwd, f) ?? 0,
    }));
    const result = scanContents(files, scanOpts);
    result.trackedIgnored = getTrackedIgnoredFiles(cwd);
    return { result, code: result.blocked ? 1 : 0, isHistory: false };
  }
  if (opts.paths.length === 0) {
    console.error('commit-guard: give --staged, --history <n> or one or more paths to scan.');
    return { result: empty, code: 2, isHistory: false };
  }
  try {
    files = collectDiskFiles(opts.paths);
  } catch (err) {
    console.error(`commit-guard: cannot read path: ${err instanceof Error ? err.message : String(err)}`);
    return { result: empty, code: 2, isHistory: false };
  }
  const result = scanContents(files, scanOpts);
  return { result, code: result.blocked ? 1 : 0, isHistory: false };
}

export function main(argv: string[] = process.argv.slice(2), cwd: string = process.cwd()): number {
  const [command, ...rest] = argv;
  if (command === '--help' || command === '-h' || command === undefined) {
    console.log(usage());
    return command === undefined ? 2 : 0;
  }
  if (command === '--version' || command === '-v') {
    console.log(`commit-guard ${VERSION}`);
    return 0;
  }
  if (command === 'init') {
    const force = rest.includes('--force');
    const wantsConfig = rest.includes('--config') || rest.length === 0 || (rest.length === 1 && force);
    if (!wantsConfig) {
      console.error('commit-guard: init only supports --config (and --force).');
      return 2;
    }
    const r = scaffoldConfig(cwd, force);
    if (!r.ok) {
      console.error(`commit-guard: ${r.reason}`);
      return 2;
    }
    console.log(`commit-guard: wrote example config to ${r.path}`);
    return 0;
  }
  if (command === 'install') {
    const r = installHook(cwd);
    if (!r.ok) {
      console.error(`commit-guard: install failed: ${r.reason}`);
      return 2;
    }
    console.log(`commit-guard: pre-commit hook installed at ${r.path}${r.backedUp ? ' (previous hook backed up to pre-commit.bak)' : ''}`);
    return 0;
  }
  if (command === 'uninstall') {
    const r = uninstallHook(cwd);
    if (!r.ok) {
      console.error(`commit-guard: uninstall failed: ${r.reason}`);
      return 2;
    }
    console.log(`commit-guard: pre-commit hook removed${r.restoredBackup ? ' (previous hook restored)' : ''}.`);
    return 0;
  }
  if (command === 'scan') {
    const parsed = parseScanArgs(rest);
    if ('error' in parsed) {
      console.error(`commit-guard: ${parsed.error}`);
      console.log(usage());
      return 2;
    }
    const { result, code, isHistory } = runScan(cwd, parsed);
    if (parsed.json) {
      console.log(JSON.stringify(result, null, 2));
    } else if (isHistory) {
      printHistoryHuman(result as HistoryResult, parsed);
    } else {
      printHuman(result as ScanResult, cwd, parsed);
    }
    return code;
  }
  console.error(`commit-guard: unknown command: ${command}`);
  console.log(usage());
  return 2;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exitCode = main();
}
