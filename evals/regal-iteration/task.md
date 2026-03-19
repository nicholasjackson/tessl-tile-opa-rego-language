# Kubernetes: Container Image Registry Validation

Write a Rego policy that validates all containers in a Kubernetes Pod use images from the approved registry (`registry.example.com`). Deny any Pod that has a container using an image from any other registry.

## Input

```json
{
  "request": {
    "kind": {"kind": "Pod"},
    "object": {
      "metadata": {"name": "my-pod"},
      "spec": {
        "containers": [
          {"name": "app", "image": "registry.example.com/myapp:latest"},
          {"name": "sidecar", "image": "docker.io/nginx:latest"}
        ]
      }
    }
  }
}
```

## Expected behaviour

- The example input must be denied — `sidecar` uses `docker.io/nginx:latest`
- A pod where all containers use `registry.example.com/...` images must be allowed
- Only validate resources with `kind == "Pod"`
- Include the container name and image in the denial message
