# Kubernetes: Namespace Policy Validation

Write a Rego policy in the package `kubernetes.namespaces` that validates Kubernetes namespace objects. The policy should:

1. Use `deny contains msg if { ... }` for collecting violations
2. Deny when the namespace name is in `data.restricted_names` — check using `input.metadata.name in data.restricted_names` (not `!= restricted_names[_]` which is a common bug)
3. Deny when a required annotation `"owner"` is missing from `input.metadata.annotations`
4. Use `sprintf` with the correct number of arguments matching the format string verbs

## Input

```json
{
  "metadata": {
    "name": "production",
    "annotations": {
      "owner": "platform-team"
    }
  }
}
```

## Data

```json
{
  "restricted_names": ["default", "kube-system", "kube-public"]
}
```

## Expected behaviour

- `production` with `owner` annotation → no violations
- `kube-system` → deny (restricted name)
- Missing `owner` annotation → deny with annotation name in message
- Both violations → two deny messages
