# Regal: Function Style — Container Security Validation

Write a Rego policy that validates container security settings in Kubernetes Pods. Use helper functions to check individual container properties. Each helper function must take the container object as an explicit argument — do not reference `input` or `data` directly inside a function body.

Check the following per container:
- The container must not run as privileged (`securityContext.privileged != true`)
- The container must declare resource limits (`resources.limits.cpu` and `resources.limits.memory`)

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
            "image": "myapp:latest",
            "securityContext": {"privileged": true},
            "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}}
          }
        ]
      }
    }
  }
}
```

## Expected behaviour

- The example input must be denied — `app` is privileged
- A container with `privileged: false` and resource limits must be allowed
- A container missing resource limits must be denied (separate violation)
- Include the container name in each denial message
