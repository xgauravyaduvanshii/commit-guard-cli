/**
 * Shannon-entropy check for commit-guard-cli.
 *
 * Some secrets have no recognisable shape — a random API token, a generated
 * password, a base64 blob. Those strings look random: their Shannon entropy
 * (bits of information per character) is far higher than ordinary code or
 * prose. This module flags long, mixed-case, high-entropy tokens as
 * *possible* secrets.
 *
 * A high-entropy finding is a hint, not proof — hashes, UUIDs and long
 * identifiers can score high too. Findings never contain the token itself:
 * the snippet reports only the token length and its entropy, so a scan
 * report is safe to paste into an issue or CI log.
 */

export const DEFAULT_ENTROPY_THRESHOLD = 4.5; // bits per character
export const DEFAULT_ENTROPY_MIN_LENGTH = 20;

export interface EntropyOptions {
  enabled?: boolean;
  threshold?: number;
  minLength?: number;
}

/** Shannon entropy of a string, in bits per character. */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function charClasses(value: string): number {
  let classes = 0;
  if (/[a-z]/.test(value)) classes++;
  if (/[A-Z]/.test(value)) classes++;
  if (/[0-9]/.test(value)) classes++;
  if (/[^A-Za-z0-9]/.test(value)) classes++;
  return classes;
}

/** Candidate tokens: long runs of token characters (base64-ish alphabet). */
const TOKEN_REGEX = /[A-Za-z0-9_\-+]{20,}={0,2}/g;

export interface HighEntropyToken {
  /** Length of the token (the token itself is never returned). */
  length: number;
  entropy: number;
  /** Byte offset of the token inside the line, for overlap checks. */
  start: number;
  end: number;
}

/**
 * Find high-entropy tokens in one line. Returns only lengths/entropies and
 * offsets — never the token text.
 */
export function findHighEntropyTokens(line: string, options: EntropyOptions = {}): HighEntropyToken[] {
  const threshold = options.threshold ?? DEFAULT_ENTROPY_THRESHOLD;
  const minLength = options.minLength ?? DEFAULT_ENTROPY_MIN_LENGTH;
  const out: HighEntropyToken[] = [];
  for (const match of line.matchAll(TOKEN_REGEX)) {
    const raw = match[0] as string;
    const token = raw.replace(/=+$/, '');
    if (token.length < minLength) continue;
    // A token made of one character class (all-lowercase words, all digits,
    // repeated characters) is an identifier or a hash, not a random secret.
    if (charClasses(token) < 2) continue;
    const entropy = shannonEntropy(token);
    if (entropy < threshold) continue;
    out.push({
      length: token.length,
      entropy,
      start: match.index ?? 0,
      end: (match.index ?? 0) + raw.length,
    });
  }
  return out;
}
