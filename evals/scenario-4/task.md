# Task: Terraform Plan Validation Policy

We use OPA to validate Terraform plans before they are applied. Write a Rego policy that prevents `aws_security_group` resources from allowing inbound SSH access (port 22) from the internet.
