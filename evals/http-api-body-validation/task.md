# HTTP API: Request Body Field Validation

Write a Rego policy that validates POST request bodies. Unknown fields (not in the allowed set) must be rejected. Required fields must be present.

## Input

```json
{
  "method": "POST",
  "path": "/api/users",
  "body": {
    "username": "alice",
    "email": "alice@example.com",
    "admin": true
  }
}
```

## Expected behaviour

- Allowed fields for `/api/users` POST: `username`, `email`, `display_name`
- Required fields: `username`, `email`
- The example input must be denied — `admin` is not an allowed field
- A body with only `username` and `email` must be allowed
- A body missing `email` must be denied
