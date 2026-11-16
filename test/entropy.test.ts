import { describe, expect, it } from 'vitest';
import { findHighEntropyTokens, shannonEntropy } from '../src/entropy.js';
import { scanText } from '../src/patterns.js';

// A genuinely random-looking token: 27 chars, mixed case + digits.
const RANDOM_TOKEN = 'xK9mQ2vL8pR4tY7wN3sD6fH1jK5';

describe('shannonEntropy', () => {
  it('is 0 for a single repeated character', () => {
    expect(shannonEntropy('aaaaaaaaaaaaaaaaaaaaaaaa')).toBe(0);
  });

  it('is 1 for two equally likely characters', () => {
    expect(shannonEntropy('abababab')).toBeCloseTo(1, 10);
  });

  it('is 2 for four equally likely characters', () => {
    expect(shannonEntropy('abcdabcd')).toBeCloseTo(2, 10);
  });

  it('scores a random-looking token well above ordinary text', () => {
    expect(shannonEntropy(RANDOM_TOKEN)).toBeGreaterThan(4.5);
    expect(shannonEntropy('hello world this is a normal sentence')).toBeLessThan(4.5);
  });
});

describe('findHighEntropyTokens', () => {
  it('flags a long mixed-case random token', () => {
    const tokens = findHighEntropyTokens(`const token = "${RANDOM_TOKEN}";`);
    expect(tokens).toHaveLength(1);
    expect(tokens[0]?.length).toBe(RANDOM_TOKEN.length);
    expect(tokens[0]?.entropy).toBeGreaterThanOrEqual(4.5);
  });

  it('ignores short tokens, single-class tokens and plain English', () => {
    expect(findHighEntropyTokens('const x = "shortToken123";')).toEqual([]);
    expect(findHighEntropyTokens(`const x = "${'a'.repeat(40)}";`)).toEqual([]);
    expect(findHighEntropyTokens('hello world this is a normal sentence here')).toEqual([]);
  });

  it('respects a higher threshold and a larger minLength', () => {
    expect(findHighEntropyTokens(`x = "${RANDOM_TOKEN}"`, { threshold: 5.5 })).toEqual([]);
    expect(findHighEntropyTokens(`x = "${RANDOM_TOKEN}"`, { minLength: 40 })).toEqual([]);
  });
});

describe('entropy findings in scanText', () => {
  it('flags a high-entropy token without ever printing it', () => {
    const findings = scanText(`const token = "${RANDOM_TOKEN}";`);
    expect(findings.map((f) => f.patternId)).toContain('high-entropy-string');
    const entropyFinding = findings.find((f) => f.patternId === 'high-entropy-string');
    expect(entropyFinding?.snippet).toContain('value redacted');
    expect(entropyFinding?.snippet).not.toContain(RANDOM_TOKEN);
    expect(entropyFinding?.snippet).toContain(`${RANDOM_TOKEN.length} chars`);
  });

  it('does not flag ordinary code', () => {
    expect(scanText('const hello = "world";\nfunction add(a, b) { return a + b; }\n')).toEqual([]);
  });

  it('honours the allowlist and commit-guard-ignore for entropy tokens', () => {
    const line = `const token = "${RANDOM_TOKEN}";`;
    expect(scanText(line, { allowlist: [RANDOM_TOKEN] })).toEqual([]);
    expect(scanText(`${line} // commit-guard-ignore`)).toEqual([]);
  });

  it('can be disabled', () => {
    expect(scanText(`const token = "${RANDOM_TOKEN}";`, { entropy: { enabled: false } })).toEqual([]);
  });

  it('does not report the same secret twice when a pattern already matched it', () => {
    const key = `sk_live_${RANDOM_TOKEN.slice(0, 24)}`;
    const findings = scanText(`STRIPE=${key}`);
    expect(findings.map((f) => f.patternId)).toEqual(['stripe-secret-key']);
  });
});
