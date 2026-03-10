# Task: RBAC Policy

Write a Rego policy for our infrastructure platform. The user's roles come from their JWT claims. Role permissions are loaded into OPA's data document.

## Input

```json
{
  "user": "bob",
  "token": {
    "sub": "bob",
    "roles": ["devops", "network_admin"]
  },
  "action": "deploy",
  "resource_type": "application"
}
```

## Data

`data.role_grants` maps each role to the actions and resource types it permits:

```json
{
  "auditor": [
    {"action": "view", "resource_type": "logs"}
  ],
  "devops": [
    {"action": "view",   "resource_type": "logs"},
    {"action": "deploy", "resource_type": "application"}
  ],
  "network_admin": [
    {"action": "configure", "resource_type": "network"}
  ]
}
```

## Expected behaviour

- `bob` (devops + network_admin) can deploy applications and configure network
- A user with only `auditor` can view logs but not deploy
- Nobody can do anything not covered by their role grants
