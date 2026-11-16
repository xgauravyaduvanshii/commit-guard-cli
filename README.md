# commit-guard-cli

A zero-dependency pre-commit guard that blocks staged secrets, `.env` / private-key files and oversized files — without ever printing a secret value.

```sh
npm install -g commit-guard-cli
commit-guard install          # install the pre-commit hook in this repo
git commit -m "..."           # the hook runs `commit-guard scan --staged`
```

## The real problem

Secrets get committed by accident every day: an AWS key pasted into a config file, a `.env` added before `.gitignore` existed, a Stripe key in a test fixture. Removing the file from staging does not help once it has been pushed — it stays in git history and on the remote, and the key has to be revoked.

commit-guard catches the common cases at commit time, before the push.

## What it checks

| Check | Result |
| --- | --- |
| AWS access keys (`AKIA…`), GitHub tokens (`ghp_…` / `github_pat_…`), Stripe secret keys (`sk_live_…` / `sk_test_…`), OpenAI-shaped keys (`sk-…`), `*_KEY` / `*_SECRET` / `*_TOKEN` / `*_PASSWORD` assignments, PEM private-key blocks, database URLs with credentials | **Block** (exit 1) |
| Staged `.env`, `.env.local`, `.env.production`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa` … (`.env.example` / `.env.sample` are allowed) | **Block** (exit 1) |
| Files over 5 MB (configurable with `--max-size-mb`); over 100 MB is also flagged because GitHub rejects such files | **Block** (exit 1) |
| Tracked files that match an ignore rule — e.g. a `.env` committed before `.gitignore` existed | **Warning**, with the exact fix: `git rm -r --cached "<file>"` |

Findings show only the pattern id, file and line — the matched value is replaced with `[REDACTED]`, so scan output is safe to paste into CI logs and issues.

## Usage

```sh
commit-guard scan --staged                     # scan staged changes (what the hook runs)
commit-guard scan src/ config.js              # scan files / directories on disk
commit-guard scan --staged --json              # machine-readable output for CI
commit-guard scan --staged --quiet             # exit code only, no output
commit-guard scan --staged --max-size-mb 10    # raise the large-file limit
commit-guard scan --staged --allowlist .commitguardallow  # one entry per line (substring or /regex/)
commit-guard install                           # install .git/hooks/pre-commit
commit-guard uninstall                         # remove it (restores a backed-up hook)
```

Exit codes: `0` pass (warnings allowed), `1` blocked, `2` usage / environment error.

### Allowlist

Create a file (one entry per line, `#` comments ignored). An entry is a plain substring, or a regex when wrapped in `/…/`. A line can also be skipped inline with a `commit-guard-ignore` comment:

```sh
# .commitguardallow
AKIAIOSFODNN7EXAMPLE
/test-only-key/
```

```js
const key = "AKIA1234567890ABCDEF"; // commit-guard-ignore — test fixture only
```

The documented AWS example key `AKIAIOSFODNN7EXAMPLE` is allowlisted by default. Nothing else is.

### If a secret was already pushed

Un-staging is not enough — the secret stays in history and on the remote. Rotate it first:

1. Revoke / rotate the secret at the provider (AWS / GitHub / Stripe / OpenAI).
2. Remove it from history, e.g. `git filter-repo` or BFG.
3. Force-push only if your team agrees — history rewrites affect everyone.

commit-guard prints this guidance when a block is found in a repo with commits and an upstream.

## Honest limits

This is a **light, beginner-friendly guard, not a full secret scanner**:

- It checks shapes, not live credentials — a match means "looks like a secret, confirm it", and a clean scan does not prove a repo is secret-free.
- It only scans staged content (or the paths you give it); it does not scan git history, and it will miss secrets split across lines, encoded (base64), or in an unusual format.
- For history scanning and deeper detection, use [gitleaks](https://github.com/gitleaks/gitleaks) or [truffleHog](https://github.com/trufflesecurity/trufflehog). commit-guard is the cheap first line of defence you install in two commands; those tools are the thorough second one.

## Install the hook

`commit-guard install` writes `.git/hooks/pre-commit`, which runs `commit-guard scan --staged`. If an unrelated hook already exists it is backed up to `pre-commit.bak` (restored by `uninstall`). If `commit-guard` is not on PATH when a commit runs, the hook warns and lets the commit proceed rather than blocking it.

## Development

Requires Node 18+. Zero runtime dependencies.

```sh
npm install
npm test        # Vitest
npm run lint    # tsc --noEmit
npm run build   # tsc -> dist/
```

Fixtures: `fixtures/repo-with-secret/` (fake, shape-valid secrets — scan exits 1) and `fixtures/repo-clean/` (scan exits 0).

## License

MIT — Copyright (c) 2026 Gaurav Kumar Yadav. See [LICENSE](LICENSE).
