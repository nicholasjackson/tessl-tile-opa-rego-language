# API Rate Limits: Tiered Default Values

Write a Rego policy in the package `api.limits` that returns a `max_requests` value based on the user's subscription tier stored in `data.user_tiers`. Use a `default` declaration for the fallback value (10 requests). Override for `"standard"` tier (100 requests) and `"premium"` tier (1000 requests). The default must be declared at the **top** of the rule group, not at the bottom.

## Input

```json
{"user_id": "alice"}
```

## Data

```json
{
  "user_tiers": {
    "alice": "premium",
    "bob": "standard"
  }
}
```

## Expected behaviour

- `alice` (premium) → `max_requests` = 1000
- `bob` (standard) → `max_requests` = 100
- `carol` (no tier / unknown) → `max_requests` = 10 (default)
