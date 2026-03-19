# HTTP API: Common Testing Pattern

Write a Rego policy that allows GET requests for users with the `read` permission, and POST requests for users with the `write` permission. All other requests are denied.

Also write a `_test.rego` file that tests the policy. The test file must be named with the `_test.rego` suffix, use the `_test` package suffix, prefix all test functions with `test_`, mock input using `with input as`, and include both a passing case and a failing case.

## Input

```json
{
  "method": "POST",
  "user": "alice"
}
```

## Data

`data.user_permissions` maps users to their permissions:

```json
{
  "alice": ["read"],
  "bob": ["read", "write"]
}
```

## Expected behaviour

- Alice (read only) is allowed GET but denied POST
- Bob (read + write) is allowed both GET and POST
- Requests from unknown users are denied
