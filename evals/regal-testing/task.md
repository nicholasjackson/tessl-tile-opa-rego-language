# Regal: Testing Style — Authorization Policy with Tests

Write a Rego policy in the package `api.authz` that allows access based on role:
- `"admin"` role → allow all methods
- `"viewer"` role → allow GET only
- Any other role → deny

Then write a test file for it following these conventions:
- Test file named `authz_test.rego` with package `api.authz_test`
- Import the policy package: `import data.api.authz`
- Reference rules via the package alias: `authz.allow`
- Give each test a unique, descriptive name
- Test at least: admin allowed, viewer GET allowed, viewer POST denied, unknown role denied

## Input

```json
{"role": "admin", "method": "GET"}
```

## Expected behaviour

- `admin` + any method → allow
- `viewer` + GET → allow
- `viewer` + POST → deny
- `guest` + GET → deny
