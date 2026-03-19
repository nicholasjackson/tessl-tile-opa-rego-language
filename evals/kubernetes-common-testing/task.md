# Kubernetes: Common Testing Pattern

Write a Rego admission policy that denies pods containing containers without CPU and memory resource limits set.

Also write a `_test.rego` file that tests the policy. The test file must be named with the `_test.rego` suffix, use the `_test` package suffix, prefix all test functions with `test_`, mock input using `with input as`, and include both a passing case (all containers have limits) and a failing case (a container is missing limits).

## Input

```json
{
  "request": {
    "kind": {"kind": "Pod"},
    "object": {
      "metadata": {"name": "my-pod"},
      "spec": {
        "containers": [
          {
            "name": "app",
            "resources": {}
          }
        ]
      }
    }
  }
}
```

## Expected behaviour

- Deny pods where any container is missing `resources.limits.cpu` or `resources.limits.memory`
- Allow pods where all containers have both limits set
- The deny message should include the container name
