# Metadata: Runtime Annotation Access

Write a Rego policy for Kubernetes pod admission that reads its own rule metadata at runtime and includes the severity level from annotations in the violation output.

The violation output must be a structured object (not a plain string) containing both the `severity` from the rule's `custom.severity` annotation and a `message` field.

## Input

```json
{
  "request": {
    "kind": {"kind": "Pod"},
    "object": {
      "metadata": {"name": "my-pod"},
      "spec": {
        "containers": [
          {"name": "app", "securityContext": {"privileged": true}}
        ]
      }
    }
  }
}
```

## Expected behaviour

- Deny privileged containers
- The violation must be a structured object: `{"severity": "HIGH", "message": "..."}`
- The severity value comes from the rule's own `# METADATA` annotation (`custom.severity: HIGH`), accessed via `rego.metadata.rule()` at runtime — not hardcoded

Also write a `_test.rego` file that tests the policy with both a passing case and a failing case.
