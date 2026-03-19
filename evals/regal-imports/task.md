# Regal: Import Conventions — JWT Authorization with Helper Library

Write two Rego files:

1. **`lib/jwt.rego`** — package `lib.jwt` with a `decode_claims(token)` function that splits a JWT by `.`, base64-decodes the second part, and JSON-parses it to return the claims object.

2. **`authz.rego`** — package `api.authz` that:
   - Imports the helper package with `import data.lib.jwt` (not individual functions)
   - Uses `jwt.decode_claims(input.token)` to get claims
   - Allows access when the `role` claim is `"admin"` or `"editor"`
   - All imports appear before any rules
   - No redundant aliases (don't alias `jwt` as `jwt`)

## Input

```json
{"token": "<jwt-string>"}
```

## Expected behaviour

- Token with `role: "admin"` → allow
- Token with `role: "editor"` → allow
- Token with `role: "viewer"` → deny
- Invalid/missing token → deny
