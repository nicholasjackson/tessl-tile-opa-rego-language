# HTTP API: Rate Limiting with Per-User Limits

Write a Rego policy that enforces rate limits. Different users have different request limits per minute. Users not in the limit table fall back to a default limit.

## Input

```json
{
  "user": "alice",
  "request_count": 120
}
```

## Data

`data.request_counts` maps users to their current request count in the last minute.

Per-user limits:
- `premium` users: 1000 requests/min
- `standard` users: 100 requests/min
- Default (unknown tier): 10 requests/min

User tiers are in `data.user_tiers`:
```json
{
  "alice": "premium",
  "bob": "standard"
}
```

## Expected behaviour

- Alice (premium) is allowed up to 1000 requests
- Bob (standard) is allowed up to 100 requests
- An unknown user is allowed up to 10 requests (default)
- `allow` is false when `input.request_count` exceeds the user's limit
