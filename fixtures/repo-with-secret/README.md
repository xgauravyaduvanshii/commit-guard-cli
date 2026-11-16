# commit-guard fixture: repo-with-secret
#
# Everything in this folder is FAKE and shape-valid only, invented for
# testing. No live credentials are in this repo, ever.
#
# Expected: `commit-guard scan fixtures/repo-with-secret` exits 1 and
# reports the AWS key, GitHub token and Stripe key in config.js, plus the
# blocked `.env` file.
