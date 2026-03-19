# HTTP API: Authorization Policy

Write a Rego policy for our API gateway. Every incoming request is checked by OPA before it reaches the service. Users authenticate with a JWT bearer token.

The policy should allow users to read their own salary record and allow managers to read their subordinates' salary records. All other requests should be denied.

## Input

```json
{
  "method": "GET",
  "path": ["finance", "salary", "alice"],
  "user": "bob",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

The JWT token is at `input.token` as a raw encoded string. Decode it with `io.jwt.decode(input.token)` to extract the payload claims (e.g. `azp`, `subordinates`, `hr`).

## Expected behaviour

- A user can GET their own salary: `input.path == ["finance", "salary", input.user]`
- A manager can GET a subordinate's salary: the subordinate's username appears in `token.payload.subordinates`
- HR members (where `token.payload.hr == true`) can GET any salary
- The token must be issued to the requesting user: `input.user == token.payload.azp`
- All other requests are denied (`default allow := false`)
