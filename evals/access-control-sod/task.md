# Access Control: Separation of Duty

Write a Rego policy that detects separation-of-duty (SOD) violations — users who hold two roles that must never be held simultaneously.

## Data

`data.user_roles` maps users to their current role assignments:

```json
{
  "alice": ["create-payment", "approver"],
  "bob": ["create-payment", "auditor"],
  "charlie": ["approve-payment", "auditor"]
}
```

The conflicting role pairs are:

```json
[
  ["create-payment", "approve-payment"],
  ["create-vendor",  "pay-vendor"]
]
```

## Expected behaviour

- `alice` has a SOD violation (holds `create-payment` and `approver` — wait, `approver` isn't in the list, but `approve-payment` is — so alice is fine)
- A user holding both `create-payment` and `approve-payment` is a violation
- The policy must produce a set of violating users
