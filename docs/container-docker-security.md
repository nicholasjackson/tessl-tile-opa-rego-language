# Container and Docker Security Policies

## Overview

This document provides comprehensive examples of using Rego to enforce container and Docker security policies. These policies help prevent security vulnerabilities by controlling how containers are configured and executed, including runtime parameters, resource constraints, network configurations, and access controls.

Container security is critical in modern cloud-native environments. OPA can be integrated with Docker's authorization plugin system to enforce fine-grained security policies at the daemon level, ensuring that containers are created and managed according to organizational security standards.

---

## 1. SECCOMP PROFILE ENFORCEMENT

### Example 1.1: Prevent Unconfined Seccomp Profiles

Blocks containers from running with unconfined seccomp profiles, which disable syscall filtering and increase attack surface.

```rego
package docker.authz

default allow := false

allow if {
    not deny
}

deny if {
    seccomp_unconfined
}

seccomp_unconfined if {
    input.Body.HostConfig.SecurityOpt[_] == "seccomp:unconfined"
}
```

### Example 1.2: Require Specific Seccomp Profile

Enforces the use of a specific seccomp profile for all containers.

```rego
package docker.authz

import rego.v1

default allow := false

allowed_seccomp_profiles := {
    "seccomp:docker/default.json",
    "seccomp:runtime/default",
}

deny contains msg if {
    input.Body.HostConfig.SecurityOpt
    not has_valid_seccomp
    msg := "container must use an approved seccomp profile"
}

has_valid_seccomp if {
    some opt in input.Body.HostConfig.SecurityOpt
    startswith(opt, "seccomp:")
    opt in allowed_seccomp_profiles
}

allow if {
    not deny
}
```

---

## 2. PRIVILEGED CONTAINER PREVENTION

### Example 2.1: Block Privileged Containers

Prevents creation of privileged containers which have access to all host devices and can bypass security restrictions.

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

### Example 2.2: Privileged Containers with Approval

Allows privileged containers only for approved users or with specific justification metadata.

```rego
package docker.authz

import rego.v1

default allow := false

privileged_users := {"admin", "security-team"}

allow if {
    not deny
}

deny contains msg if {
    input.Body.HostConfig.Privileged == true
    user := input.Headers["Authz-User"]
    not privileged_users[user]
    msg := sprintf("user %v is not authorized to run privileged containers", [user])
}

deny contains msg if {
    input.Body.HostConfig.Privileged == true
    not input.Body.Labels["privileged-justification"]
    msg := "privileged containers require 'privileged-justification' label"
}
```

---

## 3. VOLUME MOUNT RESTRICTIONS

### Example 3.1: Restrict Host Path Mounts

Limits which host directories can be mounted into containers to prevent unauthorized access to sensitive paths.

```rego
package docker.authz

import rego.v1

default allow := false

allowed_volume_paths := {"/data", "/logs", "/tmp"}

allow if {
    not deny
}

deny contains msg if {
    some bind in input.Body.HostConfig.Binds
    [host_path, container_path] := split(bind, ":")
    not is_allowed_path(host_path)
    msg := sprintf("host path %v is not in allowed volume paths", [host_path])
}

is_allowed_path(path) if {
    some allowed in allowed_volume_paths
    startswith(path, allowed)
}
```

### Example 3.2: Prevent Sensitive Directory Mounts

Explicitly blocks mounting of sensitive system directories.

```rego
package docker.authz

import rego.v1

default allow := false

blocked_paths := {
    "/etc",
    "/var/run/docker.sock",
    "/proc",
    "/sys",
    "/boot",
    "/root",
}

allow if {
    not deny
}

deny contains msg if {
    some bind in input.Body.HostConfig.Binds
    [host_path, _] := split(bind, ":")
    some blocked in blocked_paths
    startswith(host_path, blocked)
    msg := sprintf("mounting %v is prohibited for security reasons", [host_path])
}
```

---

## 4. USER-BASED DOCKER ACCESS CONTROL

### Example 4.1: Read-Only User Access

Implements fine-grained user authorization with read-only and read-write permissions.

```rego
package docker.authz

import rego.v1

default allow := false

# Allow if the user is granted read/write access
allow if {
    user_id := input.Headers["Authz-User"]
    user := users[user_id]
    not user.readOnly
}

# Allow if the user is granted read-only access and the request is a GET
allow if {
    user_id := input.Headers["Authz-User"]
    users[user_id].readOnly
    input.Method == "GET"
}

users := {
    "bob": {"readOnly": true},
    "alice": {"readOnly": false},
}
```

### Example 4.2: Role-Based Docker Access

Implements role-based access control for Docker operations.

```rego
package docker.authz

import rego.v1

default allow := false

user_roles := {
    "alice": ["developer", "deployer"],
    "bob": ["viewer"],
    "charlie": ["admin"],
}

role_permissions := {
    "viewer": {"methods": {"GET"}},
    "developer": {"methods": {"GET", "POST"}, "operations": {"create", "start", "stop"}},
    "deployer": {"methods": {"GET", "POST", "DELETE"}, "operations": {"create", "start", "stop", "remove"}},
    "admin": {"methods": {"GET", "POST", "DELETE", "PUT"}, "operations": {"*"}},
}

allow if {
    user := input.Headers["Authz-User"]
    some role in user_roles[user]
    role_allows_operation(role)
}

role_allows_operation(role) if {
    perms := role_permissions[role]
    perms.operations == {"*"}
    input.Method in perms.methods
}

role_allows_operation(role) if {
    perms := role_permissions[role]
    perms.operations != {"*"}
    input.Method in perms.methods
    operation := extract_operation(input.Path)
    operation in perms.operations
}

extract_operation(path) := operation if {
    parts := split(path, "/")
    operation := parts[count(parts) - 1]
}
```

---

## 5. CAPABILITY RESTRICTIONS

### Example 5.1: Drop Dangerous Capabilities

Requires dropping dangerous Linux capabilities from containers.

```rego
package docker.authz

import rego.v1

default allow := false

required_drop_capabilities := {
    "NET_RAW",
    "SYS_ADMIN",
    "SYS_MODULE",
    "SYS_RAWIO",
}

allow if {
    not deny
}

deny contains msg if {
    some required in required_drop_capabilities
    not capability_dropped(required)
    msg := sprintf("container must drop capability %v", [required])
}

capability_dropped(cap) if {
    some dropped in input.Body.HostConfig.CapDrop
    upper(dropped) == upper(cap)
}
```

### Example 5.2: Limit Added Capabilities

Restricts which capabilities can be added to containers.

```rego
package docker.authz

import rego.v1

default allow := false

allowed_add_capabilities := {
    "NET_BIND_SERVICE",
    "CHOWN",
    "DAC_OVERRIDE",
}

allow if {
    not deny
}

deny contains msg if {
    some cap in input.Body.HostConfig.CapAdd
    not allowed_add_capabilities[upper(cap)]
    msg := sprintf("adding capability %v is not allowed", [cap])
}
```

---

## 6. APPARMOR PROFILE ENFORCEMENT

### Example 6.1: Require AppArmor Profile

Ensures containers run with an AppArmor security profile.

```rego
package docker.authz

import rego.v1

default allow := false

approved_apparmor_profiles := {
    "apparmor:docker-default",
    "apparmor:runtime/default",
    "apparmor:docker-nginx",
}

allow if {
    not deny
}

deny contains msg if {
    not has_apparmor_profile
    msg := "container must specify an AppArmor profile"
}

has_apparmor_profile if {
    some opt in input.Body.HostConfig.SecurityOpt
    startswith(opt, "apparmor:")
    opt in approved_apparmor_profiles
}
```

---

## 7. SELINUX CONTEXT VALIDATION

### Example 7.1: Enforce SELinux Labels

Validates that containers use appropriate SELinux security contexts.

```rego
package docker.authz

import rego.v1

default allow := false

required_selinux_type := "svirt_sandbox_file_t"

allow if {
    not deny
}

deny contains msg if {
    some opt in input.Body.HostConfig.SecurityOpt
    startswith(opt, "label:")
    not valid_selinux_label(opt)
    msg := sprintf("invalid SELinux label: %v", [opt])
}

valid_selinux_label(label) if {
    contains(label, required_selinux_type)
}

deny contains msg if {
    count([opt | some opt in input.Body.HostConfig.SecurityOpt; startswith(opt, "label:")]) == 0
    msg := "container must specify SELinux security label"
}
```

---

## 8. NETWORK MODE LIMITATIONS

### Example 8.1: Restrict Host Network Mode

Prevents containers from using host network mode which shares the host's network namespace.

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

### Example 8.2: Enforce Allowed Network Modes

Restricts containers to approved network modes.

```rego
package docker.authz

import rego.v1

default allow := false

allowed_network_modes := {"bridge", "none", "container:", "custom-network"}

allow if {
    not deny
}

deny contains msg if {
    network_mode := input.Body.HostConfig.NetworkMode
    not is_allowed_network_mode(network_mode)
    msg := sprintf("network mode %v is not allowed", [network_mode])
}

is_allowed_network_mode(mode) if {
    mode in allowed_network_modes
}

is_allowed_network_mode(mode) if {
    some allowed in allowed_network_modes
    startswith(allowed, "container:")
    startswith(mode, "container:")
}
```

---

## 9. RESOURCE CONSTRAINTS

### Example 9.1: Enforce Memory Limits

Requires all containers to have memory limits to prevent resource exhaustion.

```rego
package docker.authz

import rego.v1

default allow := false

minimum_memory := 67108864  # 64MB in bytes
maximum_memory := 4294967296  # 4GB in bytes

allow if {
    not deny
}

deny contains msg if {
    memory := input.Body.HostConfig.Memory
    memory == 0
    msg := "container must specify a memory limit"
}

deny contains msg if {
    memory := input.Body.HostConfig.Memory
    memory > 0
    memory < minimum_memory
    msg := sprintf("memory limit %v is below minimum %v bytes", [memory, minimum_memory])
}

deny contains msg if {
    memory := input.Body.HostConfig.Memory
    memory > maximum_memory
    msg := sprintf("memory limit %v exceeds maximum %v bytes", [memory, maximum_memory])
}
```

### Example 9.2: Enforce CPU Constraints

Ensures containers have CPU limits to prevent CPU starvation.

```rego
package docker.authz

import rego.v1

default allow := false

minimum_cpu_shares := 256
maximum_cpu_quota := 100000
maximum_cpu_period := 100000

allow if {
    not deny
}

deny contains msg if {
    cpu_shares := input.Body.HostConfig.CpuShares
    cpu_shares > 0
    cpu_shares < minimum_cpu_shares
    msg := sprintf("CPU shares %v is below minimum %v", [cpu_shares, minimum_cpu_shares])
}

deny contains msg if {
    cpu_quota := input.Body.HostConfig.CpuQuota
    cpu_quota > maximum_cpu_quota
    msg := sprintf("CPU quota %v exceeds maximum %v", [cpu_quota, maximum_cpu_quota])
}
```

---

## 10. IMAGE SCANNING INTEGRATION

### Example 10.1: Require Scanned Images

Ensures only images that have passed security scanning can be deployed.

```rego
package docker.authz

import rego.v1

default allow := false

# Mock data - in production, query from vulnerability database
scanned_images := {
    "myregistry.com/app:v1.0": {"scanned": true, "vulnerabilities": 0},
    "myregistry.com/app:v1.1": {"scanned": true, "vulnerabilities": 2},
    "myregistry.com/nginx:latest": {"scanned": false},
}

allow if {
    not deny
}

deny contains msg if {
    image := input.Body.Image
    not scanned_images[image].scanned
    msg := sprintf("image %v has not been scanned for vulnerabilities", [image])
}

deny contains msg if {
    image := input.Body.Image
    vulns := scanned_images[image].vulnerabilities
    vulns > 0
    msg := sprintf("image %v has %v known vulnerabilities", [image, vulns])
}
```

---

## 11. IMAGE SIGNATURE VERIFICATION

### Example 11.1: Require Signed Images

Enforces that only cryptographically signed images can be deployed.

```rego
package docker.authz

import rego.v1

default allow := false

trusted_registries := {"myregistry.com", "docker.io/verified"}

allow if {
    not deny
}

deny contains msg if {
    image := input.Body.Image
    not is_from_trusted_registry(image)
    msg := sprintf("image %v is not from a trusted registry", [image])
}

is_from_trusted_registry(image) if {
    some registry in trusted_registries
    startswith(image, registry)
}

deny contains msg if {
    image := input.Body.Image
    not has_signature_verification_label
    msg := "image must have signature verification label"
}

has_signature_verification_label if {
    input.Body.Labels["signature-verified"] == "true"
}
```

---

## 12. REGISTRY AUTHENTICATION POLICIES

### Example 12.1: Enforce Private Registry Usage

Ensures containers only use images from approved private registries.

```rego
package docker.authz

import rego.v1

default allow := false

approved_registries := {
    "mycompany.azurecr.io",
    "gcr.io/mycompany",
    "123456789.dkr.ecr.us-east-1.amazonaws.com",
}

allow if {
    not deny
}

deny contains msg if {
    image := input.Body.Image
    not uses_approved_registry(image)
    msg := sprintf("image %v must come from approved registry", [image])
}

uses_approved_registry(image) if {
    some registry in approved_registries
    startswith(image, registry)
}

deny contains msg if {
    image := input.Body.Image
    contains(image, "docker.io")
    msg := "public Docker Hub images are not allowed"
}
```

---

## 13. CONTAINER RUNTIME RESTRICTIONS

### Example 13.1: Enforce Specific Runtime

Restricts which container runtimes can be used.

```rego
package docker.authz

import rego.v1

default allow := false

allowed_runtimes := {"runc", "kata-runtime"}

allow if {
    not deny
}

deny contains msg if {
    runtime := input.Body.HostConfig.Runtime
    runtime != ""
    not allowed_runtimes[runtime]
    msg := sprintf("runtime %v is not allowed", [runtime])
}
```

---

## 14. PORT BINDING RESTRICTIONS

### Example 14.1: Restrict Privileged Port Bindings

Prevents binding to privileged ports (below 1024) without authorization.

```rego
package docker.authz

import rego.v1

default allow := false

privileged_port_users := {"admin", "network-team"}

allow if {
    not deny
}

deny contains msg if {
    some port, bindings in input.Body.HostConfig.PortBindings
    some binding in bindings
    host_port := to_number(binding.HostPort)
    host_port < 1024
    user := input.Headers["Authz-User"]
    not privileged_port_users[user]
    msg := sprintf("user %v cannot bind to privileged port %v", [user, host_port])
}
```

### Example 14.2: Prevent Binding to Sensitive Ports

Blocks binding to specific sensitive ports.

```rego
package docker.authz

import rego.v1

default allow := false

blocked_ports := {22, 23, 3389, 5900}  # SSH, Telnet, RDP, VNC

allow if {
    not deny
}

deny contains msg if {
    some port, bindings in input.Body.HostConfig.PortBindings
    some binding in bindings
    host_port := to_number(binding.HostPort)
    blocked_ports[host_port]
    msg := sprintf("binding to port %v is prohibited", [host_port])
}
```

---

## 15. DEVICE ACCESS CONTROL

### Example 15.1: Restrict Device Access

Limits which devices containers can access.

```rego
package docker.authz

import rego.v1

default allow := false

allowed_devices := {
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
}

allow if {
    not deny
}

deny contains msg if {
    some device in input.Body.HostConfig.Devices
    not allowed_devices[device.PathOnHost]
    msg := sprintf("access to device %v is not allowed", [device.PathOnHost])
}
```

---

## 16. IPC NAMESPACE ISOLATION

### Example 16.1: Prevent Host IPC Mode

Blocks containers from using the host's IPC namespace.

```rego
package docker.authz

import rego.v1

default allow := false

allow if {
    not deny
}

deny contains msg if {
    input.Body.HostConfig.IpcMode == "host"
    msg := "containers cannot use host IPC namespace"
}
```

---

## 17. PID NAMESPACE RESTRICTIONS

### Example 17.1: Restrict PID Namespace Sharing

Prevents containers from sharing PID namespace with host.

```rego
package docker.authz

import rego.v1

default allow := false

allow if {
    not deny
}

deny contains msg if {
    input.Body.HostConfig.PidMode == "host"
    msg := "containers cannot use host PID namespace"
}

deny contains msg if {
    pid_mode := input.Body.HostConfig.PidMode
    startswith(pid_mode, "container:")
    not approved_pid_sharing
    msg := sprintf("PID namespace sharing with %v requires approval", [pid_mode])
}

approved_pid_sharing if {
    input.Body.Labels["pid-sharing-approved"] == "true"
}
```

---

## 18. USER NAMESPACE MAPPING

### Example 18.1: Require User Namespace Remapping

Enforces user namespace remapping for improved isolation.

```rego
package docker.authz

import rego.v1

default allow := false

allow if {
    not deny
}

deny contains msg if {
    userns_mode := input.Body.HostConfig.UsernsMode
    userns_mode == ""
    not is_read_only_operation
    msg := "container must use user namespace remapping"
}

is_read_only_operation if {
    input.Method == "GET"
}

deny contains msg if {
    userns_mode := input.Body.HostConfig.UsernsMode
    userns_mode == "host"
    msg := "containers cannot disable user namespace remapping"
}
```

---

## 19. COMPREHENSIVE SECURITY POLICY

### Example 19.1: Multi-Layer Security Enforcement

Combines multiple security checks into a comprehensive policy.

```rego
package docker.authz

import rego.v1

default allow := false

allow if {
    count(deny) == 0
}

# Prevent privileged containers
deny contains "privileged containers are not allowed" if {
    input.Body.HostConfig.Privileged == true
}

# Require seccomp profile
deny contains "unconfined seccomp profile is not allowed" if {
    input.Body.HostConfig.SecurityOpt[_] == "seccomp:unconfined"
}

# Prevent host network
deny contains "host network mode is not allowed" if {
    input.Body.HostConfig.NetworkMode == "host"
}

# Prevent host PID namespace
deny contains "host PID namespace is not allowed" if {
    input.Body.HostConfig.PidMode == "host"
}

# Prevent host IPC namespace
deny contains "host IPC namespace is not allowed" if {
    input.Body.HostConfig.IpcMode == "host"
}

# Require memory limits
deny contains "memory limit must be specified" if {
    input.Body.HostConfig.Memory == 0
}

# Prevent mounting Docker socket
deny contains "mounting Docker socket is not allowed" if {
    some bind in input.Body.HostConfig.Binds
    contains(bind, "/var/run/docker.sock")
}

# Require non-root user
deny contains "container must run as non-root user" if {
    user := input.Body.User
    user == "root"
}

deny contains "container must specify a user" if {
    not input.Body.User
}

# Validate registry
deny contains msg if {
    image := input.Body.Image
    not uses_approved_registry(image)
    msg := sprintf("image %v must come from approved registry", [image])
}

uses_approved_registry(image) if {
    approved_registries := {"myregistry.com", "gcr.io/mycompany"}
    some registry in approved_registries
    startswith(image, registry)
}
```

---

## 20. AUDIT AND COMPLIANCE

### Example 20.1: Audit Logging and Compliance Reporting

Implements comprehensive audit logging for Docker operations.

```rego
package docker.authz

import rego.v1

default allow := false

# Main authorization decision
allow if {
    count(violations) == 0
}

# Track all violations for audit purposes
violations contains violation if {
    input.Body.HostConfig.Privileged == true
    violation := {
        "severity": "high",
        "category": "privileged-container",
        "message": "privileged container attempted",
        "user": input.Headers["Authz-User"],
        "timestamp": time.now_ns(),
    }
}

violations contains violation if {
    input.Body.HostConfig.SecurityOpt[_] == "seccomp:unconfined"
    violation := {
        "severity": "high",
        "category": "seccomp-disabled",
        "message": "unconfined seccomp profile attempted",
        "user": input.Headers["Authz-User"],
        "timestamp": time.now_ns(),
    }
}

violations contains violation if {
    input.Body.HostConfig.Memory == 0
    violation := {
        "severity": "medium",
        "category": "resource-limits",
        "message": "no memory limit specified",
        "user": input.Headers["Authz-User"],
        "timestamp": time.now_ns(),
    }
}

# Compliance check results
compliance_status := {
    "compliant": count(violations) == 0,
    "violations": violations,
    "total_violations": count(violations),
    "user": input.Headers["Authz-User"],
    "operation": sprintf("%v %v", [input.Method, input.Path]),
}
```

---

## Summary

These examples demonstrate comprehensive container and Docker security policies using Rego:

1. **Seccomp Profile Enforcement** - Prevents unconfined seccomp and enforces approved profiles
2. **Privileged Container Prevention** - Blocks or controls privileged container creation
3. **Volume Mount Restrictions** - Limits host path mounts and blocks sensitive directories
4. **User-Based Access Control** - Implements read-only and role-based permissions
5. **Capability Restrictions** - Controls Linux capabilities that can be added or dropped
6. **AppArmor Profile Enforcement** - Requires approved AppArmor security profiles
7. **SELinux Context Validation** - Enforces SELinux security labels
8. **Network Mode Limitations** - Restricts host network and enforces allowed modes
9. **Resource Constraints** - Enforces memory and CPU limits
10. **Image Scanning Integration** - Requires vulnerability-scanned images
11. **Image Signature Verification** - Enforces cryptographically signed images
12. **Registry Authentication** - Restricts to approved private registries
13. **Container Runtime Restrictions** - Limits allowed container runtimes
14. **Port Binding Restrictions** - Controls privileged and sensitive port bindings
15. **Device Access Control** - Limits device access within containers
16. **IPC Namespace Isolation** - Prevents host IPC namespace sharing
17. **PID Namespace Restrictions** - Controls PID namespace sharing
18. **User Namespace Mapping** - Enforces user namespace remapping
19. **Comprehensive Security** - Multi-layer security enforcement
20. **Audit and Compliance** - Audit logging and compliance reporting

All examples use modern Rego v1 syntax with the `import rego.v1` statement and follow best practices for production deployments. These policies can be combined and customized to meet specific organizational security requirements.
