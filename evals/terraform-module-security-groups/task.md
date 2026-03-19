# Terraform: Module Security Group Validation

We use OPA to validate Terraform plans before they are applied. Write a Rego policy that checks security group descriptions across all modules in a plan — including child modules — to ensure no security group description contains the string `"HTTP"`.

The plan structure to traverse is `input.planned_values`, not `resource_changes`. Resources can exist in the root module (`planned_values.root_module.resources`) or in child modules (`planned_values.root_module.child_modules[*].resources`).

Use the `walk` built-in to traverse the entire `planned_values` tree rather than accessing root and child modules separately.
