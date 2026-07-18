# Security policy

## Data classification

This repository is public. Treat every committed byte and every historical commit as publicly readable.

Never commit:

- Personal names or profiles
- Identifiable family photographs
- Home, school, workplace, or lodging addresses tied to a person
- Phone numbers or email addresses
- Reservation numbers or payment information
- Credentials, tokens, cookies, private keys, or recovery codes

## Release gate

Run:

```sh
python scripts/pii_scan.py .
```

GitHub Actions must pass the same scan before deployment. Private denylist terms belong in the `PII_PRIVATE_TERMS` Actions secret and must never be committed.

## Access control

Cloudflare should proxy the entire domain. Cloudflare Access email OTP should protect private routes, including `/trip` and `/trip/*`. Cloudflare protection does not replace repository sanitization.

## Incident response

If personal or secret data is committed:

1. Remove it from the current tree.
2. Rotate any exposed credential immediately.
3. Rewrite Git history.
4. Force-push the cleaned refs.
5. Review forks, pull requests, caches, and other clones for remaining copies.
