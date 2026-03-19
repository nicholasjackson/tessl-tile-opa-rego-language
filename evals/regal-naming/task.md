# Regal: Naming Conventions — RBAC Policy

Write a Rego policy in the package `rbac.authz` that implements role-based access control for API endpoints. Users have roles stored in `data.user_roles`. Roles have permissions stored in `data.role_permissions`. Allow access when the user's role grants the required permission for the requested endpoint and method.

## Input

```json
{
  "user": "alice",
  "method": "GET",
  "path": "/api/reports"
}
```

## Data

```json
{
  "user_roles": {"alice": "engineer", "bob": "admin"},
  "role_permissions": {
    "engineer": ["reports:read"],
    "admin": ["reports:read", "reports:write", "users:read", "users:write"]
  }
}
```

## Expected behaviour

- Alice (engineer) can GET `/api/reports` (has `reports:read`) — allow
- Alice (engineer) cannot POST `/api/reports` (no `reports:write`) — deny
- Bob (admin) can POST `/api/reports` — allow
- Unknown user with no role — deny
