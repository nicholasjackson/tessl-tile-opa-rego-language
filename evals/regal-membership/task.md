# HTTP API: Department-Based Access Control

Write a Rego policy that allows access to API endpoints based on the user's department. Each endpoint has a set of allowed departments stored in `data.endpoint_access`. Deny access if the user's department is not in the allowed set.

## Input

```json
{
  "method": "GET",
  "path": "/api/reports",
  "user": {"department": "engineering"}
}
```

## Data

`data.endpoint_access` maps paths to lists of allowed departments:

```json
{
  "/api/reports": ["engineering", "finance", "management"],
  "/api/admin":   ["management"]
}
```

## Expected behaviour

- Engineering department can access `/api/reports` — allow
- HR department cannot access `/api/reports` — deny
- Engineering department cannot access `/api/admin` — deny
- Deny by default if no matching path in `data.endpoint_access`
