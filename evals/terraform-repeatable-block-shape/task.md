# Terraform: Repeatable Block Serialization Shape

Write an OPA policy that denies `docker_container` resources being created or
updated without dropping all Linux capabilities.

The container must set `capabilities { drop = ["ALL"] }` in its Terraform
configuration. Deny the resource if this is missing, or if `"ALL"` is not
present in the `drop` list.

Note: in `terraform show -json` plan output, a repeatable HCL block (one
written as `capabilities { ... }` rather than as an attribute) is serialized
as a **list** of 0 or 1 objects, not as a bare object. A container with no
`capabilities` block at all will show `"capabilities": []` in the plan JSON —
not a missing key and not `{}`.
