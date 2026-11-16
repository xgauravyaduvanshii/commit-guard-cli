// Fixture: a repo file containing FAKE, shape-valid secrets.
// These tokens are invented for testing only — they are not live credentials.
// commit-guard should BLOCK this file.
const AWS_KEY = "AKIA1234567890ABCDEF";
const GITHUB_TOKEN = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const STRIPE_KEY = "sk_live_abcdefghijklmnop1234";
module.exports = { AWS_KEY, GITHUB_TOKEN, STRIPE_KEY };
