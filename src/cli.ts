#!/usr/bin/env node
/**
 * commit-guard — zero-dependency pre-commit guard.
 *
 *   commit-guard scan --staged [--json] [--quiet] [--max-size-mb N] [--allowlist FILE]
 *   commit-guard scan <path...>          scan files / directories on disk
 *   commit-guard install                 install .git/hooks/pre-commit
 *   commit-guard uninstall               remove it (restores a backed-up hook)
 *
 * Exit codes: 0 = pass (warnings allowed), 1 = blocked, 2 = usage / environment error.
 * Scan output never contains a secret value — findings are redacted at the
 * pattern layer (see src/patterns.ts).
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { getStagedContent, getStagedFiles, getStagedSize, getTrackedIgnoredFiles, hasCommits, hasUpstream, isGitRepo, untrackCommand } from './git.js';
import { installHook, uninstallHook } from './hooks.js';
import { parseAllowlistFile } from './patterns.js';
import { DEFAULT_MAX_FILE_BYTES, formatBytes, scanContents, type ScanResult } from './scan.js';

export const VERSION = '0.1.0';

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
    '  commit-guard scan --staged [--json] [--quiet] [--max-size-mb N] [--allowlist FILE]',
    '  commit-guard scan <path...> [--json] [--quiet] [--max-size-mb N] [--allowlist FILE]',
    '  commit-guard install',
    '  commit-guard uninstall',
    '  commit-guard --help | --version',
    '',
    'Exit codes: 0 pass, 1 blocked, 2 usage / environment error.',
    'Default large-file limit: 5 MB (GitHub rejects files over 100 MB).',
  ].join('\n');
}

interface ScanOptions {
  staged: boolean;
  paths: string[];
  json: boolean;
  quiet: boolean;
  maxFileBytes: number;
  allowlist: string[];
}

function parseScanArgs(args: string[]): ScanOptions | { error: string } {
  const opts: ScanOptions = {
    staged: false,
    paths: [],
    json: false,
    quiet: false,
    maxFileBytes: DEFAULT_MAX_FILE_BYTES,
    allowlist: [],
  };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--staged') opts.staged = true;
    else if (arg === '--json') opts.json = true;
    else if (arg === '--quiet') opts.quiet = true;
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

export function runScan(cwd: string, opts: ScanOptions): { result: ScanResult; code: number } {
  let files: Array<{ path: string; content: string | null; bytes: number }>;
  if (opts.staged) {
    if (!isGitRepo(cwd)) {
      console.error('commit-guard: --staged needs a git repository.');
      return { result: { findings: [], blockedFiles: [], largeFiles: [], trackedIgnored: [], blocked: false }, code: 2 };
    }
    const staged = getStagedFiles(cwd);
    files = staged.map((f) => ({
      path: f,
      content: getStagedContent(cwd, f),
      bytes: getStagedSize(cwd, f) ?? 0,
    }));
    const result = scanContents(files, { allowlist: opts.allowlist, maxFileBytes: opts.maxFileBytes });
    result.trackedIgnored = getTrackedIgnoredFiles(cwd);
    return { result, code: result.blocked ? 1 : 0 };
  }
  if (opts.paths.length === 0) {
    console.error('commit-guard: give --staged or one or more paths to scan.');
    return { result: { findings: [], blockedFiles: [], largeFiles: [], trackedIgnored: [], blocked: false }, code: 2 };
  }
  try {
    files = collectDiskFiles(opts.paths);
  } catch (err) {
    console.error(`commit-guard: cannot read path: ${err instanceof Error ? err.message : String(err)}`);
    return { result: { findings: [], blockedFiles: [], largeFiles: [], trackedIgnored: [], blocked: false }, code: 2 };
  }
  const result = scanContents(files, { allowlist: opts.allowlist, maxFileBytes: opts.maxFileBytes });
  return { result, code: result.blocked ? 1 : 0 };
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
    const { result, code } = runScan(cwd, parsed);
    if (parsed.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      printHuman(result, cwd, parsed);
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
