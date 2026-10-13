# Disposable email domain data

Used by `users/disposable_email.py` (Django) and by the Cognito Pre Sign-up
Lambda in `deploy/cognito_pre_signup/`. Nothing is fetched at request time.

| File | Purpose |
|---|---|
| `disposable_email_blocklist.conf` | Byte-identical copy of the upstream blocklist. Do not edit by hand. |
| `SOURCE.json` | Upstream commit, date, licence, domain count and SHA-256 of the blocklist. |
| `allowlist.conf` | Project-owned exceptions for confirmed false positives. Edit by hand, with review. |
| `LICENSE.txt` | Upstream licence (CC0 1.0, public domain). |

Source: https://github.com/disposable-email-domains/disposable-email-domains

## Matching rules

- The email domain is trimmed, lowercased, has a trailing dot removed and is
  IDNA-encoded (so `bücher.example` is compared as `xn--bcher-kva.example`).
- The domain and each parent domain are checked, so `sub.mailinator.com` is
  blocked because `mailinator.com` is listed. `notmailinator.com` is not.
- A domain is allowed if it, or any parent domain, is in the allowlist.
- An unlisted domain is not proof that an address is legitimate.

## Updating the blocklist

Updates are manual and reviewed. Nothing updates the list automatically.

```bash
# Preview: download, validate and compare, without writing anything
python manage.py update_disposable_email_domains --ref <upstream-commit-sha>

# Write the new blocklist and SOURCE.json
python manage.py update_disposable_email_domains --ref <upstream-commit-sha> --write
```

Then review the diff, run
`pytest users/tests/test_disposable_email.py users/tests/test_cognito_pre_signup_lambda.py`,
rebuild the Lambda package, and deploy the backend and the Lambda together, so
both enforce the same list.
