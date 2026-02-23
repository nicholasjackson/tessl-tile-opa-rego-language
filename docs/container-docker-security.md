# Docker Authorization with OPA (opa-docker-authz)

## Overview

The [opa-docker-authz](https://github.com/open-policy-agent/opa-docker-authz) plugin integrates OPA directly into the Docker daemon as an authorization plugin. Before Docker executes any API request — creating containers, starting them, pulling images — it sends the request to OPA. Your Rego policy decides whether to allow or deny the operation.

This is the canonical way to enforce container security policies at the daemon level using OPA.

---

## How the Plugin Works

When the plugin is active, Docker forwards every API call to OPA with a JSON input describing the operation:

```json
{
  "Body": {
    "Image": "nginx:latest",
    "HostConfig": {
      "Privileged": false,
      "SecurityOpt": ["seccomp:unconfined"],
      "Binds": ["/data:/data:ro"]
    },
    "User": "1000"
  },
  "Headers": {
    "Authz-User": "alice"
  },
  "Method": "POST",
  "Path": "/v1.40/containers/create"
}
```

Key fields:

| Field | Description |
|-------|-------------|
| `input.Body` | The Docker API request body (mirrors the Docker API spec) |
| `input.Body.HostConfig` | Runtime configuration — privileges, mounts, capabilities, network |
| `input.Headers["Authz-User"]` | The authenticated Docker user making the request |
| `input.Method` | HTTP method (`GET`, `POST`, `DELETE`) |
| `input.Path` | Docker API path (e.g. `/v1.40/containers/create`) |

OPA evaluates `data.docker.authz.allow`. If it returns `true`, Docker proceeds. If `false` or undefined, the request is denied.

---

## Policy Structure

All policies use `package docker.authz`. The canonical pattern is **default deny with allow-if-not-denied**:

```rego
package docker.authz

import rego.v1

default allow := false

allow if {
    not deny
}
```

Deny rules are expressed as a set of messages — when any rule fires, the request is denied:

```rego
deny contains msg if {
    input.Body.HostConfig.Privileged == true
    msg := "privileged containers are not allowed"
}
```

---

## 1. READ-ONLY USER ENFORCEMENT

The introductory example from the official OPA Docker authorization tutorial: users marked as read-only can only issue GET requests.

```rego
package docker.authz

import rego.v1

default allow := false

# Read-write users can do anything
allow if {
    user_id := input.Headers["Authz-User"]
    user := users[user_id]
    not user.readOnly
}

# Read-only users can only GET
allow if {
    user_id := input.Headers["Authz-User"]
    users[user_id].readOnly
    input.Method == "GET"
}

users := {
    "bob":   {"readOnly": true},
    "alice": {"readOnly": false},
}
```

---

## 2. PRIVILEGED CONTAINER PREVENTION

Privileged containers have full access to all host devices and bypass most security restrictions. This is almost always the first policy teams enforce.

```rego
package docker.authz

import rego.v1

default allow := false

allow if {
    not deny
}

deny contains msg if {
    input.Body.HostConfig.Privileged == true
    msg := "privileged containers are not allowed"
}
```

---

## 3. SECCOMP PROFILE ENFORCEMENT

`seccomp:unconfined` disables syscall filtering entirely. Enforce that containers never run without a seccomp profile:

```rego
package docker.authz

import rego.v1

default allow := false

allow if {
    not deny
}

deny contains msg if {
    "seccomp:unconfined" in input.Body.HostConfig.SecurityOpt
    msg := "unconfined seccomp profile is not allowed"
}
```

### Example 3.2: Require an Approved Seccomp Profile

```rego
package docker.authz

import rego.v1

default allow := false

approved_profiles := {
    "seccomp:docker/default.json",
    "seccomp:runtime/default",
}

allow if {
    not deny
}

deny contains msg if {
    input.Body.HostConfig.SecurityOpt
    not has_approved_seccomp
    msg := "container must use an approved seccomp profile"
}

has_approved_seccomp if {
    some opt in input.Body.HostConfig.SecurityOpt
    opt in approved_profiles
}
```

---

## 4. SENSITIVE BIND MOUNT PREVENTION

Block containers from mounting the Docker socket or other sensitive host paths, which would allow container escape:

```rego
package docker.authz

import rego.v1

default allow := false

blocked_paths := {
    "/var/run/docker.sock",
    "/etc",
    "/proc",
    "/sys",
    "/boot",
}

allow if {
    not deny
}

deny contains msg if {
    some bind in input.Body.HostConfig.Binds
    [host_path, _] := split(bind, ":")
    some blocked in blocked_paths
    startswith(host_path, blocked)
    msg := sprintf("mounting %v is prohibited", [host_path])
}
```

---

## 5. CAPABILITY RESTRICTIONS

Drop dangerous Linux capabilities that most containers never need:

```rego
package docker.authz

import rego.v1

default allow := false

required_drops := {"NET_RAW", "SYS_ADMIN", "SYS_MODULE"}

allow if {
    not deny
}

deny contains msg if {
    some cap in required_drops
    not capability_dropped(cap)
    msg := sprintf("container must drop capability %v", [cap])
}

capability_dropped(cap) if {
    some dropped in input.Body.HostConfig.CapDrop
    upper(dropped) == upper(cap)
}
```

---

## 6. NETWORK MODE RESTRICTIONS

Prevent containers from using host network mode, which shares the host's network namespace:

```rego
package docker.authz

import rego.v1

default allow := false

allow if {
    not deny
}

deny contains msg if {
    input.Body.HostConfig.NetworkMode == "host"
    msg := "containers cannot use host network mode"
}
```

---

## 7. COMBINED SECURITY POLICY

A production policy typically combines multiple deny rules. Because deny is a set, all violations are collected and any of them blocks the request:

```rego
package docker.authz

import rego.v1

default allow := false

allow if {
    not deny
}

deny contains "privileged containers are not allowed" if {
    input.Body.HostConfig.Privileged == true
}

deny contains "unconfined seccomp profile is not allowed" if {
    "seccomp:unconfined" in input.Body.HostConfig.SecurityOpt
}

deny contains "host network mode is not allowed" if {
    input.Body.HostConfig.NetworkMode == "host"
}

deny contains "host PID namespace is not allowed" if {
    input.Body.HostConfig.PidMode == "host"
}

deny contains "host IPC namespace is not allowed" if {
    input.Body.HostConfig.IpcMode == "host"
}

deny contains "mounting Docker socket is not allowed" if {
    some bind in input.Body.HostConfig.Binds
    contains(bind, "/var/run/docker.sock")
}
```

---

## 8. TESTING POLICIES

Use `opa test` to verify your policy against known-good and known-bad inputs:

```rego
package docker.authz_test

import data.docker.authz
import rego.v1

test_allow_normal_container if {
    authz.allow with input as {
        "Body": {
            "Image": "nginx:latest",
            "HostConfig": {
                "Privileged": false,
                "SecurityOpt": ["seccomp:runtime/default"],
            },
        },
        "Method": "POST",
        "Path": "/v1.40/containers/create",
    }
}

test_deny_privileged_container if {
    not authz.allow with input as {
        "Body": {"HostConfig": {"Privileged": true}},
        "Method": "POST",
        "Path": "/v1.40/containers/create",
    }
}

test_deny_unconfined_seccomp if {
    not authz.allow with input as {
        "Body": {
            "HostConfig": {
                "Privileged": false,
                "SecurityOpt": ["seccomp:unconfined"],
            },
        },
        "Method": "POST",
        "Path": "/v1.40/containers/create",
    }
}
```

Run tests with:

```bash
opa test . -v
```

---

## Summary

The `opa-docker-authz` plugin follows a consistent pattern:

1. `package docker.authz` — the required package name for the plugin
2. `default allow := false` — deny by default
3. `allow if { not deny }` — allow when nothing is denied
4. `deny contains msg if { ... }` — collect all violations

The `input` shape mirrors the Docker API: `input.Body.HostConfig` for runtime config, `input.Headers["Authz-User"]` for the requesting user, and `input.Method` / `input.Path` for the operation type.
