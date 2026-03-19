# Regal: Boolean Structure — Pod Security Policy

Write a Rego policy in the package `kubernetes.security` that validates Kubernetes pod specs. The policy should:

1. Define an `allow` rule (boolean) that is `true` only when there are no `violations`
2. Collect `violations` as an incremental set using `violations contains msg if { ... }` (not a comprehension assigned to a variable)
3. Add violations for:
   - Any container where `securityContext.privileged == true`
   - Any container missing `resources.limits`

## Input

```json
{
  "spec": {
    "template": {
      "spec": {
        "containers": [
          {
            "name": "app",
            "securityContext": {"privileged": false},
            "resources": {"limits": {"cpu": "500m", "memory": "128Mi"}}
          }
        ]
      }
    }
  }
}
```

## Expected behaviour

- Compliant pod (no privileged, has limits) → `allow` is true, `violations` is empty
- Privileged container → violation message containing the container name
- Container without resource limits → violation message containing the container name
