# Regal: Annotations — RBAC Authorization Policy

Write a fully annotated Rego policy in the package `rbac.authz` with metadata annotations:

1. **Package annotation** with `title`, `description`, and `authors` fields
2. **`allow` rule** annotated with `title`, `description`, and `entrypoint: true`
3. **`user_role` rule** annotated with `title` and `description`

The policy logic:
- `default allow := false`
- Allow when the user has a role and that role includes the required permission
- `user_role` returns the role from `data.user_roles[input.user]`
- Required permission is derived from the action and resource in `input`

Metadata blocks must be **immediately above** the rule they annotate — no blank lines between the `# METADATA` block and the rule.

## Input

```json
{
  "user": "alice",
  "action": "read",
  "resource": "reports"
}
```

## Data

```json
{
  "user_roles": {"alice": "engineer"},
  "role_permissions": {"engineer": ["reports:read"]}
}
```

## Expected behaviour

- `alice` with `read` on `reports` → allow (has `reports:read`)
- `alice` with `write` on `reports` → deny (no `reports:write`)
- Unknown user → deny
