/**
 * Secret patterns for commit-guard-cli.
 *
 * These are shape checks, not proof a value is a live secret. A match means
 * "this looks like a secret — a human should confirm it". Findings never
 * include the matched value itself (see `redact`), only the pattern id,
 * file and line, so a scan report is safe to paste into an issue or CI log.
 *
 * The documented AWS example key AKIAIOSFODNN7EXAMPLE is allowlisted by
 * default because it appears in AWS's own docs. Nothing else is.
 */

import { DEFAULT_ENTROPY_MIN_LENGTH, DEFAULT_ENTROPY_THRESHOLD, findHighEntropyTokens, type EntropyOptions } from './entropy.js';

export interface SecretPattern {
  id: string;
  name: string;
  description: string;
  regex: RegExp;
}

export interface Finding {
  patternId: string;
  patternName: string;
  line: number;
  /** Redacted snippet: the matched text is replaced with `[REDACTED]`. */
  snippet: string;
}

export const DEFAULT_PATTERNS: SecretPattern[] = [
  {
    id: 'aws-access-key',
    name: 'AWS access key ID',
    description: 'AKIA + 16 uppercase letters/digits.',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    id: 'github-token',
    name: 'GitHub token',
    description: 'ghp_/gho_/ghu_/ghs_/ghr_ classic tokens or github_pat_ fine-grained tokens.',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
  },
  {
    id: 'stripe-secret-key',
    name: 'Stripe secret key',
    description: 'sk_live_ / sk_test_ (and restricted rk_live_ / rk_test_) keys.',
    regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
  },
  {
    id: 'openai-api-key',
    name: 'OpenAI API key',
    description: 'sk- followed by 20+ letters/digits (the classic OpenAI shape).',
    regex: /\bsk-[A-Za-z0-9]{20,}\b/g,
  },
  {
    id: 'generic-secret-assignment',
    name: 'Secret-looking assignment',
    description: 'A *_KEY / *_SECRET / *_TOKEN / *_PASSWORD variable assigned a value of 8+ characters.',
    regex: /\b[A-Z0-9_]{2,}(?:_KEY|_SECRET|_TOKEN|_PASSWORD)\s*=\s*['"]?[^\s'"]{8,}/g,
  },
  {
    id: 'pem-private-key',
    name: 'PEM private key block',
    description: '-----BEGIN ... PRIVATE KEY----- header.',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g,
  },
  {
    id: 'database-url',
    name: 'Database URL with credentials',
    description: 'postgres/mysql/mongodb/redis URL containing user:password@host.',
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/g,
  },
];

/** Values that are documentation examples, never live secrets. */
export const DEFAULT_ALLOWLIST: string[] = ['AKIAIOSFODNN7EXAMPLE'];

/**
 * A line is allowlisted when it contains `commit-guard-ignore`, or when any
 * allowlist entry matches it. An entry is treated as a RegExp when it is
 * wrapped in `/.../`; otherwise it is a plain substring.
 */
export function isAllowlisted(line: string, allowlist: readonly string[]): boolean {
  if (line.includes('commit-guard-ignore')) return true;
  for (const entry of allowlist) {
    if (!entry) continue;
    if (entry.startsWith('/') && entry.endsWith('/') && entry.length > 2) {
      try {
        if (new RegExp(entry.slice(1, -1)).test(line)) return true;
      } catch {
        // Invalid regex in the allowlist: fall through to substring match.
        if (line.includes(entry)) return true;
      }
    } else if (line.includes(entry)) {
      return true;
    }
  }
  return false;
}

/** Replace every regex match in `text` with `[REDACTED]`. Never returns a secret. */
export function redact(text: string, regex: RegExp): string {
  const re = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : `${regex.flags}g`);
  return text.replace(re, '[REDACTED]');
}

export interface ScanTextOptions {
  allowlist?: readonly string[];
  patterns?: readonly SecretPattern[];
  /** High-entropy check; enabled by default (threshold 4.5, min length 20). */
  entropy?: EntropyOptions;
}

/** Scan one text (a file's staged content) line by line. */
export function scanText(
  text: string,
  options: ScanTextOptions = {},
): Finding[] {
  const allowlist = [...DEFAULT_ALLOWLIST, ...(options.allowlist ?? [])];
  const patterns = options.patterns ?? DEFAULT_PATTERNS;
  const entropyEnabled = options.entropy?.enabled !== false;
  const findings: Finding[] = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (isAllowlisted(line, allowlist)) continue;
    const lineFindings: Finding[] = [];
    // Byte ranges of pattern matches on this line, so the entropy check
    // does not report the same secret a second time under another name.
    const matchedRanges: Array<[number, number]> = [];
    for (const pattern of patterns) {
      const re = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : `${pattern.regex.flags}g`);
      let matched = false;
      for (const m of line.matchAll(re)) {
        matched = true;
        matchedRanges.push([m.index ?? 0, (m.index ?? 0) + m[0].length]);
      }
      if (matched) {
        lineFindings.push({
          patternId: pattern.id,
          patternName: pattern.name,
          line: i + 1,
          snippet: redact(line.trim(), pattern.regex).slice(0, 200),
        });
      }
    }
    // One line, one story: when a specific pattern (AWS, GitHub, Stripe…)
    // already matched, the catch-all *_KEY/*_SECRET assignment adds only noise.
    const specific = lineFindings.filter((f) => f.patternId !== 'generic-secret-assignment');
    findings.push(...(specific.length > 0 ? specific : lineFindings));
    if (entropyEnabled) {
      for (const token of findHighEntropyTokens(line, {
        threshold: options.entropy?.threshold ?? DEFAULT_ENTROPY_THRESHOLD,
        minLength: options.entropy?.minLength ?? DEFAULT_ENTROPY_MIN_LENGTH,
      })) {
        // Skip tokens that are (part of) a pattern match on the same line.
        if (matchedRanges.some(([s, e]) => token.start < e && token.end > s)) continue;
        findings.push({
          patternId: 'high-entropy-string',
          patternName: 'High-entropy string (possible secret)',
          line: i + 1,
          // Never the token itself — only its length and entropy.
          snippet: `high-entropy token: ${token.length} chars, entropy ${token.entropy.toFixed(1)} bits/char — value redacted`,
        });
      }
    }
  }
  return findings;
}

/** Parse an allowlist file: one entry per line, `#` comments and blanks ignored. */
export function parseAllowlistFile(content: string): string[] {
  return content
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('#'));
}
