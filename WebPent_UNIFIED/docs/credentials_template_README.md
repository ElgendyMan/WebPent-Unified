# Credentials Template — Operator Guide (WP-K)

`credentials_template.json` is a **machine-consumed** file: every top-level
key is parsed as a principal profile by the real runtime loader
(`webpent.cli.loaders.load_creds_file`, consumed by `webpent scan
--creds-file` and `webpent hunt --credentials-file`). Documentation must
never occupy a profile slot inside the JSON — that is exactly the defect
class fixed here (NF-L0-02: the shipped `_readme` string profile made the
real loader reject the whole file with
`ValueError: profile '_readme' must be a JSON object.`).

## How to use

1. Copy the template: `cp credentials_template.json my_engagement_credentials.json`
2. Fill **both** principals (`owner` + `foreign`) with real values for your
   AUTHORIZED target.
   - `owner` = the principal that OWNS the object you will test access to.
   - `foreign` = an unrelated account that must NOT see the owner's data.
3. Keep the filled copy in a gitignored path and delete it after the
   engagement. NEVER commit the filled copy.
4. Run: `webpent hunt --target <url> --scope <scope file> --credentials-file
   my_engagement_credentials.json` (or `webpent scan ... --creds-file ...`).
   The POC recorder consumes these as session tokens at recording time via
   `WEBPENT_POC_OWNER_TOKEN` / `WEBPENT_POC_FOREIGN_TOKEN` (env or CLI flags).

## Profile contract (enforced by the real loader — fail-closed)

Allowed profile fields are exactly the loader's `_ALLOWED_PROFILE_FIELDS`:
`name, role, credentials, username, password, email, token, cookies,
session_cookies, headers, owned_object_ids, owned_ids, owned_urls, auth_type,
login_url, protected_url, validation_url, login_fields, surface_paths,
identity_paths, register_if_unauthorized, registration_url,
registration_fields, registration_extra`. Unknown fields, non-object
profiles, and profiles without credentials/session material are REJECTED
before any target interaction.

## API-key principals (form-session alternative)

Express an API-key principal through loader-supported fields only — the
header name/value go in `headers`, and `validation_url` is REQUIRED (the
runtime is fail-closed: without it the key profile is rejected,
`validation_url_required`, because any 200 from the target root would mark
any key as valid):

```json
{
  "api_owner": {
    "role": "owner",
    "auth_type": "api_key",
    "headers": {"X-API-Key": "REPLACE_ME_KEY"},
    "validation_url": "https://your-authorized-target.example/v1/me"
  }
}
```

## Why this file has no comments

JSON has no comment syntax, and the loader rejects every top-level key that
is not a valid profile object. All guidance lives in this README (and in
`docs/CAMPAIGN_GUIDE.md`). This round-trip discipline is enforced by
`tests/team1_acceptance/test_template_contracts.py`, which loads every
shipped template through its REAL runtime consumer under contract test.
