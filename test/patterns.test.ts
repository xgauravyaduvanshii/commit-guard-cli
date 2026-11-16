import { describe, expect, it } from 'vitest';
import { isAllowlisted, parseAllowlistFile, redact, scanText } from '../src/patterns.js';

describe('secret patterns', () => {
  it('detects an AWS access key ID', () => {
    const findings = scanText('const key = "AKIA1234567890ABCDEF";');
    expect(findings.map((f) => f.patternId)).toContain('aws-access-key');
    expect(findings[0]?.line).toBe(1);
  });

  it('does not flag the documented AWS example key', () => {
    expect(scanText('const key = "AKIAIOSFODNN7EXAMPLE";')).toEqual([]);
  });

  it('detects GitHub classic and fine-grained tokens', () => {
    expect(scanText(`token = "ghp_${'a'.repeat(36)}"`).map((f) => f.patternId)).toContain('github-token');
    expect(scanText(`token = "github_pat_${'a'.repeat(22)}"`).map((f) => f.patternId)).toContain('github-token');
  });

  it('detects Stripe live/test secret keys', () => {
    expect(scanText('STRIPE=sk_live_abcdefghijklmnop1234').map((f) => f.patternId)).toContain('stripe-secret-key');
    expect(scanText('STRIPE=sk_test_abcdefghijklmnop1234').map((f) => f.patternId)).toContain('stripe-secret-key');
  });

  it('detects an OpenAI-shaped key', () => {
    const key = `sk-${'a'.repeat(48)}`;
    expect(scanText(`OPENAI_API_KEY=${key}`).map((f) => f.patternId)).toContain('openai-api-key');
  });

  it('detects *_KEY / *_SECRET / *_TOKEN / *_PASSWORD assignments', () => {
    expect(scanText('MY_API_SECRET=supersecretvalue123').map((f) => f.patternId)).toContain('generic-secret-assignment');
    expect(scanText('DB_PASSWORD=hunter2hunter2').map((f) => f.patternId)).toContain('generic-secret-assignment');
  });

  it('detects PEM private-key blocks and database URLs with credentials', () => {
    expect(scanText('-----BEGIN PRIVATE KEY-----').map((f) => f.patternId)).toContain('pem-private-key');
    expect(scanText('postgres://user:s3cretpass@db.example.com:5432/app').map((f) => f.patternId)).toContain('database-url');
    expect(scanText('mongodb+srv://user:s3cretpass@cluster.example.net/app').map((f) => f.patternId)).toContain('database-url');
  });

  it('passes clean text', () => {
    expect(scanText('const hello = "world";\n// nothing secret here\n')).toEqual([]);
  });

  it('never returns the secret value in a finding', () => {
    const secret = `AKIA${'1'.repeat(16)}`;
    const findings = scanText(`key = "${secret}"`);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.snippet).not.toContain(secret);
      expect(f.snippet).toContain('[REDACTED]');
    }
    expect(redact(`key = "${secret}"`, /\bAKIA[0-9A-Z]{16}\b/g)).not.toContain(secret);
  });

  it('honours an inline commit-guard-ignore and an allowlist entry', () => {
    const secret = `AKIA${'1'.repeat(16)}`;
    expect(scanText(`key = "${secret}" // commit-guard-ignore`)).toEqual([]);
    expect(scanText(`key = "${secret}"`, { allowlist: [secret] })).toEqual([]);
    expect(scanText(`key = "${secret}"`, { allowlist: ['/AKIA[0-9]+/'] })).toEqual([]);
  });

  it('parses an allowlist file, ignoring blanks and comments', () => {
    expect(parseAllowlistFile('# comment\n\nAKIAIOSFODNN7EXAMPLE\n  /foo/  \n')).toEqual([
      'AKIAIOSFODNN7EXAMPLE',
      '/foo/',
    ]);
  });

  it('isAllowlisted matches substrings and /regex/ entries', () => {
    expect(isAllowlisted('hello world', ['world'])).toBe(true);
    expect(isAllowlisted('abc123', ['/^abc\\d+$/'])).toBe(true);
    expect(isAllowlisted('abc123', ['zzz'])).toBe(false);
  });
});
