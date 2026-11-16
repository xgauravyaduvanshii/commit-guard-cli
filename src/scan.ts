import type { EntropyOptions } from './entropy.js';
import { scanText, type Finding, type SecretPattern } from './patterns.js';

export const DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB
export const GITHUB_MAX_FILE_BYTES = 100 * 1024 * 1024; // 100 MB — GitHub rejects larger files

export interface FileFinding extends Finding {
  file: string;
}

export interface LargeFile {
  file: string;
  bytes: number;
  /** True once the file would be rejected outright by GitHub. */
  exceedsGitHubLimit: boolean;
}

export interface ScanResult {
  findings: FileFinding[];
  blockedFiles: string[];
  largeFiles: LargeFile[];
  /** Tracked files that match an ignore rule — warnings, not blocks. */
  trackedIgnored: string[];
  blocked: boolean;
}

/** Basenames / extensions that must never be committed. */
export function isBlockedFile(file: string, denyList: readonly string[] = []): boolean {
  const base = file.split('/').pop() ?? file;
  for (const entry of denyList) {
    if (!entry) continue;
    if (base === entry || base.endsWith(entry)) return true;
  }
  if (base === '.env') return true;
  if (base.startsWith('.env.') && !['.example', '.sample', '.template'].some((s) => base.endsWith(s))) {
    return true;
  }
  const lower = base.toLowerCase();
  return (
    lower.endsWith('.pem') ||
    lower.endsWith('.key') ||
    lower.endsWith('.p12') ||
    lower.endsWith('.pfx') ||
    lower === 'id_rsa' ||
    lower === 'id_ed25519' ||
    lower === 'id_ecdsa'
  );
}

export function checkLargeFile(file: string, bytes: number, maxBytes: number): LargeFile | null {
  if (bytes <= maxBytes) return null;
  return { file, bytes, exceedsGitHubLimit: bytes > GITHUB_MAX_FILE_BYTES };
}

export interface ScanContentOptions {
  allowlist?: readonly string[];
  maxFileBytes?: number;
  /** Extra secret patterns (added to the built-ins). */
  patterns?: readonly SecretPattern[];
  /** Extra blocked-file entries from commit-guard.json. */
  denyList?: readonly string[];
  entropy?: EntropyOptions;
}

/** Scan already-read file contents (used by the CLI and the tests). */
export function scanContents(
  files: ReadonlyArray<{ path: string; content: string | null; bytes: number }>,
  options: ScanContentOptions = {},
): ScanResult {
  const maxBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const findings: FileFinding[] = [];
  const blockedFiles: string[] = [];
  const largeFiles: LargeFile[] = [];

  for (const file of files) {
    if (isBlockedFile(file.path, options.denyList)) blockedFiles.push(file.path);
    const large = checkLargeFile(file.path, file.bytes, maxBytes);
    if (large) largeFiles.push(large);
    if (file.content !== null) {
      for (const f of scanText(file.content, {
        allowlist: options.allowlist,
        patterns: options.patterns,
        entropy: options.entropy,
      })) {
        findings.push({ ...f, file: file.path });
      }
    }
  }

  return {
    findings,
    blockedFiles,
    largeFiles,
    trackedIgnored: [],
    blocked: findings.length > 0 || blockedFiles.length > 0 || largeFiles.length > 0,
  };
}

export function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}
