# Access Control: Common Testing Pattern

Write a Rego policy that denies access when the requesting user does not have the required role for the action.

Also write a `_test.rego` file that tests the policy. The test file must be named with the `_test.rego` suffix, use the `_test` package suffix, prefix all test functions with `test_`, mock input using `with input as`, and include both a passing case (user has the required role) and a failing case (user does not have the required role).

## Input

```json
{
  "user": "alice",
  "action": "delete",
  "roles": ["viewer"]
}
```

## Data

`data.role_permissions` maps roles to permitted actions:

```json
{
  "admin": ["read", "write", "delete"],
  "editor": ["read", "write"],
  "viewer": ["read"]
}
```

## Expected behaviour

- `allow` is true when the user has a role that permits the requested action
- `allow` is false otherwise
- Alice (viewer) is denied `delete`
- A user with `admin` role is allowed `delete`
