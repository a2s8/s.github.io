# Private static portal

Static site for `sripathi.one`.

## Privacy

- Do not commit names, personal profiles, photographs of identifiable people, addresses, phone numbers, email addresses, booking confirmations, payment details, or precise private locations.
- Run `python scripts/pii_scan.py .` before every commit.
- The deployment workflow repeats the scan on every push and pull request.
- Private routes must also be protected by Cloudflare Access. Edge authentication does not make committed data private.

## Current routes

- `/` - neutral portal
- `/trip/` - share-safe mobile trip plan
