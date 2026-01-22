# Infrastructure as Code Policy Validation with Rego

This document provides comprehensive examples of using Rego for Infrastructure as Code (IaC) validation, covering Terraform plans, AWS CloudFormation templates, and general infrastructure security policies.

## Overview

Infrastructure as Code validation with OPA enables:
- Pre-deployment validation of infrastructure changes
- Enforcement of security and compliance requirements
- Cost control and blast radius management
- Consistent naming and tagging standards
- Least privilege access control

---

## 1. BLAST RADIUS CONTROL FOR CHANGE MANAGEMENT

Control the scope of infrastructure changes to prevent large-scale disruptions.

```rego
package terraform.analysis

import input as tfplan

########################
# Parameters for Policy
########################

blast_radius := 30

weights := {
    "aws_autoscaling_group": {"delete": 100, "create": 10, "modify": 1},
    "aws_instance": {"delete": 10, "create": 1, "modify": 1},
}

resource_types := {"aws_autoscaling_group", "aws_instance", "aws_iam", "aws_launch_configuration"}

#########
# Policy
#########

default authz := false

authz if {
    score < blast_radius
    not touches_iam
}

score := s if {
    all_resources := [x |
        some resource_type, crud in weights
        del := crud.delete * num_deletes[resource_type]
        new := crud.create * num_creates[resource_type]
        mod := crud.modify * num_modifies[resource_type]
        x := (del + new) + mod
    ]
    s := sum(all_resources)
}

touches_iam if {
    all_resources := resources.aws_iam
    count(all_resources) > 0
}

num_deletes[resource_type] := count(resources) if {
    resources := [r | r := resource_changes[_]; r.type == resource_type; r.change.actions[_] == "delete"]
}

num_creates[resource_type] := count(resources) if {
    resources := [r | r := resource_changes[_]; r.type == resource_type; r.change.actions[_] == "create"]
}

num_modifies[resource_type] := count(resources) if {
    resources := [r | r := resource_changes[_]; r.type == resource_type; r.change.actions[_] == "update"]
}
```

**Description**: Calculates a weighted score for Terraform plan changes based on resource types and operations. Prevents high-impact changes (score >= 30) and any IAM modifications from being auto-approved.

---

## 2. S3 BUCKET ENCRYPTION REQUIREMENTS

Ensure all S3 buckets are created with server-side encryption enabled.

```rego
package terraform.analysis

import input as tfplan

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_s3_bucket"
    r.change.actions[_] == "create"
    not r.change.after.server_side_encryption_configuration
    msg := sprintf("S3 bucket %v does not have encryption enabled", [r.address])
}

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_s3_bucket_server_side_encryption_configuration"
    r.change.actions[_] == "create"
    not encryption_algorithm_valid(r)
    msg := sprintf("S3 bucket %v uses invalid encryption algorithm", [r.address])
}

encryption_algorithm_valid(resource) if {
    algo := resource.change.after.rule[_].apply_server_side_encryption_by_default[_].sse_algorithm
    algo in {"AES256", "aws:kms"}
}
```

**Description**: Validates that S3 buckets have encryption configured and use approved encryption algorithms (AES256 or KMS).

---

## 3. S3 BUCKET VERSIONING ENFORCEMENT

Require versioning to be enabled on all S3 buckets for data protection.

```rego
package terraform.analysis

import input as tfplan

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_s3_bucket"
    r.change.actions[_] in {"create", "update"}
    not has_versioning_enabled(r)
    msg := sprintf("S3 bucket %v must have versioning enabled", [r.address])
}

has_versioning_enabled(resource) if {
    resource.change.after.versioning[_].enabled == true
}

# Also check separate versioning resource
deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_s3_bucket_versioning"
    r.change.actions[_] in {"create", "update"}
    r.change.after.versioning_configuration[_].status != "Enabled"
    msg := sprintf("S3 bucket versioning %v must be Enabled", [r.address])
}
```

**Description**: Ensures S3 buckets have versioning enabled to protect against accidental deletion and enable point-in-time recovery.

---

## 4. REQUIRED TAGS ENFORCEMENT

Enforce mandatory tags across all cloud resources for cost tracking and governance.

```rego
package terraform.analysis

import input as tfplan

required_tags := ["Environment", "Owner", "CostCenter", "Project"]

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.change.actions[_] != "delete"
    supports_tags(r.type)
    tags := object.get(r.change.after, "tags", {})
    some required_tag in required_tags
    not tags[required_tag]
    msg := sprintf("Resource %v missing required tag: %v", [r.address, required_tag])
}

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.change.actions[_] != "delete"
    supports_tags(r.type)
    tags := object.get(r.change.after, "tags", {})
    some tag_key, tag_value in tags
    tag_value == ""
    msg := sprintf("Resource %v has empty tag value for: %v", [r.address, tag_key])
}

supports_tags(resource_type) if {
    resource_type in {
        "aws_instance",
        "aws_s3_bucket",
        "aws_rds_cluster",
        "aws_lambda_function",
        "aws_dynamodb_table",
        "aws_ebs_volume",
    }
}
```

**Description**: Validates that taggable resources have all required tags with non-empty values for proper resource management and cost allocation.

---

## 5. IAM POLICY PROTECTION AND LEAST PRIVILEGE

Prevent overly permissive IAM policies and enforce least privilege principles.

```rego
package terraform.analysis

import input as tfplan

# Deny IAM policies with wildcard actions on all resources
deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type in {"aws_iam_policy", "aws_iam_role_policy"}
    r.change.actions[_] in {"create", "update"}
    policy := json.unmarshal(r.change.after.policy)
    statement := policy.Statement[_]
    statement.Effect == "Allow"
    statement.Action == "*"
    statement.Resource == "*"
    msg := sprintf("IAM policy %v grants wildcard permissions (*:*)", [r.address])
}

# Deny policies that allow privilege escalation
deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type in {"aws_iam_policy", "aws_iam_role_policy"}
    r.change.actions[_] in {"create", "update"}
    policy := json.unmarshal(r.change.after.policy)
    statement := policy.Statement[_]
    statement.Effect == "Allow"
    dangerous_action := statement.Action[_]
    dangerous_action in privilege_escalation_actions
    msg := sprintf("IAM policy %v allows privilege escalation via %v", [r.address, dangerous_action])
}

privilege_escalation_actions := {
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:PassRole",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "glue:CreateDevEndpoint",
}
```

**Description**: Blocks IAM policies that grant excessive permissions or allow privilege escalation, enforcing least privilege access control.

---

## 6. SECURITY GROUP VALIDATION - NO OPEN PORTS

Prevent security groups from exposing services to the internet on dangerous ports.

```rego
package terraform.analysis

import input as tfplan

dangerous_ports := {22, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 9300}

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_security_group"
    r.change.actions[_] in {"create", "update"}
    ingress := r.change.after.ingress[_]
    ingress.cidr_blocks[_] == "0.0.0.0/0"
    port := ingress.from_port
    port in dangerous_ports
    msg := sprintf("Security group %v allows public access on dangerous port %v", [r.address, port])
}

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_security_group_rule"
    r.change.actions[_] in {"create", "update"}
    r.change.after.type == "ingress"
    r.change.after.cidr_blocks[_] == "0.0.0.0/0"
    port := r.change.after.from_port
    port in dangerous_ports
    msg := sprintf("Security group rule %v allows public access on dangerous port %v", [r.address, port])
}

# Also deny unrestricted ingress on all ports
deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_security_group"
    r.change.actions[_] in {"create", "update"}
    ingress := r.change.after.ingress[_]
    ingress.cidr_blocks[_] == "0.0.0.0/0"
    ingress.from_port == 0
    ingress.to_port == 65535
    msg := sprintf("Security group %v allows unrestricted public access on all ports", [r.address])
}
```

**Description**: Validates security groups to prevent public exposure of sensitive services like SSH, RDP, databases, and other dangerous ports.

---

## 7. SECURITY GROUP APPROVED PROTOCOLS

Ensure security groups only use approved network protocols.

```rego
package terraform.analysis

import input as tfplan

approved_protocols := {"tcp", "udp", "icmp"}

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_security_group"
    r.change.actions[_] in {"create", "update"}
    rule := r.change.after.ingress[_]
    protocol := lower(rule.protocol)
    protocol != "-1"  # -1 means all protocols
    not protocol in approved_protocols
    msg := sprintf("Security group %v uses unapproved protocol: %v", [r.address, protocol])
}

# Warn about all protocols (-1)
warn contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_security_group"
    r.change.actions[_] in {"create", "update"}
    rule := r.change.after.ingress[_]
    rule.protocol == "-1"
    msg := sprintf("Security group %v allows all protocols (-1), consider restricting", [r.address])
}
```

**Description**: Restricts security groups to use only approved network protocols and warns when all protocols are allowed.

---

## 8. CLOUDFORMATION S3 BUCKET ACCESS CONTROL

CloudFormation hook policy to enforce S3 bucket security configurations.

```rego
package system

main := {
    "allow": count(deny) == 0,
    "violations": deny,
}

deny contains msg if {
    bucket_create_or_update
    not bucket_is_private
    msg := sprintf("S3 Bucket %s 'AccessControl' attribute value must be 'Private'", [input.resource.id])
}

deny contains msg if {
    bucket_create_or_update
    not block_public_acls
    msg := sprintf("S3 Bucket %s must block public ACLs", [input.resource.id])
}

deny contains msg if {
    bucket_create_or_update
    not block_public_policy
    msg := sprintf("S3 Bucket %s must block public bucket policies", [input.resource.id])
}

bucket_create_or_update if {
    input.resource.type == "AWS::S3::Bucket"
    input.action in {"CREATE", "UPDATE"}
}

bucket_is_private if {
    input.resource.properties.AccessControl == "Private"
}

block_public_acls if {
    input.resource.properties.PublicAccessBlockConfiguration.BlockPublicAcls == "true"
}

block_public_policy if {
    input.resource.properties.PublicAccessBlockConfiguration.BlockPublicPolicy == "true"
}
```

**Description**: CloudFormation hook policy that validates S3 buckets have private access control and block public access configurations before deployment.

---

## 9. CLOUDFORMATION EC2 INSTANCE TYPE RESTRICTIONS

Limit which EC2 instance types can be provisioned to control costs.

```rego
package system

allowed_instance_types := {"t2.micro", "t2.small", "t2.medium", "t3.micro", "t3.small", "t3.medium"}

deny contains msg if {
    input.resource.type == "AWS::EC2::Instance"
    input.action in {"CREATE", "UPDATE"}
    instance_type := input.resource.properties.InstanceType
    not allowed_instance_types[instance_type]
    msg := sprintf("Instance type %v is not allowed. Allowed types: %v", [instance_type, allowed_instance_types])
}

# Ensure instances have proper monitoring
warn contains msg if {
    input.resource.type == "AWS::EC2::Instance"
    input.action in {"CREATE", "UPDATE"}
    not input.resource.properties.Monitoring
    msg := sprintf("EC2 instance %v should have detailed monitoring enabled", [input.resource.id])
}
```

**Description**: CloudFormation policy that restricts EC2 instance types to approved list and recommends enabling detailed monitoring.

---

## 10. TERRAFORM MODULE SECURITY GROUP VALIDATION

Validate security groups don't use insecure protocols across modules.

```rego
package terraform.module

deny contains msg if {
    some r
    desc := resources[r].values.description
    contains(desc, "HTTP")
    msg := sprintf("No security groups should be using HTTP. Resource in violation: %v", [r.address])
}

resources contains r if {
    some path, value
    walk(input.planned_values, [path, value])
    some r in module_resources(path, value)
}

module_resources(path, value) := value if {
    reverse_index(path, 1) == "resources"
    reverse_index(path, 2) == "root_module"
}

module_resources(path, value) := value if {
    reverse_index(path, 1) == "resources"
    reverse_index(path, 3) == "child_modules"
}

reverse_index(path, idx) := path[count(path) - idx]
```

**Description**: Walks Terraform plan structure including child modules to ensure no security groups use insecure HTTP protocol.

---

## 11. RDS ENCRYPTION AT REST REQUIREMENT

Ensure all RDS database instances and clusters have encryption at rest enabled.

```rego
package terraform.analysis

import input as tfplan

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_db_instance"
    r.change.actions[_] in {"create", "update"}
    not r.change.after.storage_encrypted
    msg := sprintf("RDS instance %v must have storage encryption enabled", [r.address])
}

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_rds_cluster"
    r.change.actions[_] in {"create", "update"}
    not r.change.after.storage_encrypted
    msg := sprintf("RDS cluster %v must have storage encryption enabled", [r.address])
}

# Require KMS for production databases
deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type in {"aws_db_instance", "aws_rds_cluster"}
    r.change.actions[_] in {"create", "update"}
    tags := object.get(r.change.after, "tags", {})
    tags.Environment == "production"
    not r.change.after.kms_key_id
    msg := sprintf("Production database %v must use KMS encryption", [r.address])
}
```

**Description**: Validates RDS instances and clusters have encryption enabled, requiring KMS for production environments.

---

## 12. RDS BACKUP RETENTION REQUIREMENTS

Enforce backup retention policies for RDS databases.

```rego
package terraform.analysis

import input as tfplan

minimum_backup_retention := 7
production_backup_retention := 30

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_db_instance"
    r.change.actions[_] in {"create", "update"}
    retention := object.get(r.change.after, "backup_retention_period", 0)
    retention < minimum_backup_retention
    msg := sprintf("RDS instance %v backup retention (%v days) is below minimum (%v days)", [r.address, retention, minimum_backup_retention])
}

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_db_instance"
    r.change.actions[_] in {"create", "update"}
    tags := object.get(r.change.after, "tags", {})
    tags.Environment == "production"
    retention := object.get(r.change.after, "backup_retention_period", 0)
    retention < production_backup_retention
    msg := sprintf("Production RDS instance %v requires %v days backup retention (current: %v)", [r.address, production_backup_retention, retention])
}
```

**Description**: Ensures RDS instances have adequate backup retention periods with stricter requirements for production databases.

---

## 13. LAMBDA FUNCTION CONFIGURATION VALIDATION

Validate Lambda function security and operational configurations.

```rego
package terraform.analysis

import input as tfplan

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_lambda_function"
    r.change.actions[_] in {"create", "update"}
    not r.change.after.dead_letter_config
    msg := sprintf("Lambda function %v should have dead letter queue configured", [r.address])
}

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_lambda_function"
    r.change.actions[_] in {"create", "update"}
    timeout := r.change.after.timeout
    timeout > 300
    msg := sprintf("Lambda function %v timeout (%v seconds) exceeds maximum (300 seconds)", [r.address, timeout])
}

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_lambda_function"
    r.change.actions[_] in {"create", "update"}
    not r.change.after.tracing_config
    msg := sprintf("Lambda function %v should have X-Ray tracing enabled", [r.address])
}

# Ensure Lambda functions in VPC have proper networking
deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_lambda_function"
    r.change.actions[_] in {"create", "update"}
    vpc_config := r.change.after.vpc_config
    count(vpc_config) > 0
    subnet_count := count(vpc_config[0].subnet_ids)
    subnet_count < 2
    msg := sprintf("Lambda function %v in VPC should span at least 2 subnets for high availability", [r.address])
}
```

**Description**: Validates Lambda functions have proper operational configurations including DLQ, reasonable timeouts, tracing, and multi-AZ deployment.

---

## 14. VPC AND SUBNET CONFIGURATION POLICIES

Enforce VPC and subnet architecture best practices.

```rego
package terraform.analysis

import input as tfplan

# Require VPC flow logs for network monitoring
deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_vpc"
    r.change.actions[_] == "create"
    vpc_id := r.address
    not has_flow_logs(vpc_id)
    msg := sprintf("VPC %v must have flow logs enabled", [r.address])
}

has_flow_logs(vpc_address) if {
    some r in tfplan.resource_changes
    r.type == "aws_flow_log"
    r.change.actions[_] == "create"
    contains(r.change.after.vpc_id, vpc_address)
}

# Ensure subnets are properly tagged with tier
deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_subnet"
    r.change.actions[_] in {"create", "update"}
    tags := object.get(r.change.after, "tags", {})
    not tags.Tier
    msg := sprintf("Subnet %v must have Tier tag (public/private/database)", [r.address])
}

# Validate subnet CIDR sizes
deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_subnet"
    r.change.actions[_] in {"create", "update"}
    cidr := r.change.after.cidr_block
    cidr_parts := split(cidr, "/")
    prefix_length := to_number(cidr_parts[1])
    prefix_length > 28
    msg := sprintf("Subnet %v CIDR /%v is too small (minimum /28)", [r.address, prefix_length])
}
```

**Description**: Enforces VPC flow logs, proper subnet tagging, and validates subnet CIDR sizing for proper network architecture.

---

## 15. EBS VOLUME ENCRYPTION REQUIREMENTS

Require encryption for all EBS volumes.

```rego
package terraform.analysis

import input as tfplan

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_ebs_volume"
    r.change.actions[_] == "create"
    not r.change.after.encrypted
    msg := sprintf("EBS volume %v must be encrypted", [r.address])
}

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_instance"
    r.change.actions[_] == "create"
    ebs := r.change.after.ebs_block_device[_]
    not ebs.encrypted
    msg := sprintf("EC2 instance %v has unencrypted EBS volume", [r.address])
}

# Require KMS encryption for sensitive data volumes
deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_ebs_volume"
    r.change.actions[_] == "create"
    tags := object.get(r.change.after, "tags", {})
    tags.DataClassification in {"sensitive", "confidential"}
    not r.change.after.kms_key_id
    msg := sprintf("EBS volume %v with sensitive data must use KMS encryption", [r.address])
}
```

**Description**: Ensures all EBS volumes are encrypted, with KMS requirement for volumes containing sensitive data.

---

## 16. KMS KEY USAGE POLICIES

Validate proper KMS key configuration and rotation.

```rego
package terraform.analysis

import input as tfplan

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_kms_key"
    r.change.actions[_] in {"create", "update"}
    not r.change.after.enable_key_rotation
    msg := sprintf("KMS key %v must have automatic key rotation enabled", [r.address])
}

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_kms_key"
    r.change.actions[_] in {"create", "update"}
    not r.change.after.deletion_window_in_days
    msg := sprintf("KMS key %v must specify deletion window", [r.address])
}

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_kms_key"
    r.change.actions[_] in {"create", "update"}
    window := r.change.after.deletion_window_in_days
    window < 7
    msg := sprintf("KMS key %v deletion window (%v days) is too short (minimum 7 days)", [r.address, window])
}

# Require proper key descriptions
deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_kms_key"
    r.change.actions[_] == "create"
    description := object.get(r.change.after, "description", "")
    count(description) < 10
    msg := sprintf("KMS key %v must have meaningful description (minimum 10 characters)", [r.address])
}
```

**Description**: Enforces KMS key rotation, deletion windows, and proper documentation for encryption key management.

---

## 17. RESOURCE NAMING CONVENTIONS

Enforce consistent naming standards across infrastructure resources.

```rego
package terraform.analysis

import input as tfplan

import future.keywords.contains
import future.keywords.if

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.change.actions[_] in {"create", "update"}
    supports_naming(r.type)
    name := get_resource_name(r)
    not valid_name_format(name, r.type)
    msg := sprintf("Resource %v name '%v' does not follow naming convention", [r.address, name])
}

supports_naming(resource_type) if {
    resource_type in {
        "aws_instance",
        "aws_s3_bucket",
        "aws_lambda_function",
        "aws_dynamodb_table",
        "aws_rds_cluster",
    }
}

get_resource_name(resource) := name if {
    name := object.get(resource.change.after, "name", "")
}

get_resource_name(resource) := name if {
    name := object.get(resource.change.after, "bucket", "")
}

get_resource_name(resource) := name if {
    name := object.get(resource.change.after, "function_name", "")
}

# Naming format: {env}-{service}-{resource-type}-{identifier}
# Example: prod-api-lambda-processor
valid_name_format(name, _) if {
    parts := split(name, "-")
    count(parts) >= 3
    parts[0] in {"dev", "staging", "prod"}
}

# S3 buckets must follow DNS-compliant naming
valid_name_format(name, "aws_s3_bucket") if {
    count(name) >= 3
    count(name) <= 63
    regex.match(`^[a-z0-9][a-z0-9-]*[a-z0-9]$`, name)
    not contains(name, "..")
}
```

**Description**: Validates resource names follow organizational naming conventions including environment prefixes and DNS compliance for S3 buckets.

---

## 18. COST ESTIMATION AND BUDGET ENFORCEMENT

Prevent creation of resources that exceed cost thresholds.

```rego
package terraform.analysis

import input as tfplan

# Estimated monthly costs for common instance types (USD)
instance_costs := {
    "t2.micro": 8.50,
    "t2.small": 17.00,
    "t2.medium": 34.00,
    "t3.micro": 7.50,
    "t3.small": 15.00,
    "t3.medium": 30.00,
    "m5.large": 70.00,
    "m5.xlarge": 140.00,
    "r5.large": 91.00,
    "r5.xlarge": 182.00,
}

monthly_budget := 1000

total_estimated_cost := cost if {
    costs := [c |
        r := tfplan.resource_changes[_]
        r.type == "aws_instance"
        r.change.actions[_] == "create"
        instance_type := r.change.after.instance_type
        c := instance_costs[instance_type]
    ]
    cost := sum(costs)
}

deny contains msg if {
    total_estimated_cost > monthly_budget
    msg := sprintf("Estimated monthly cost $%.2f exceeds budget $%.2f", [total_estimated_cost, monthly_budget])
}

# Warn about expensive instance types
warn contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_instance"
    r.change.actions[_] == "create"
    instance_type := r.change.after.instance_type
    cost := instance_costs[instance_type]
    cost > 100
    msg := sprintf("Instance %v uses expensive type %v (~$%.2f/month)", [r.address, instance_type, cost])
}
```

**Description**: Estimates monthly infrastructure costs and prevents deployments that exceed budget thresholds.

---

## 19. MULTI-REGION DEPLOYMENT POLICIES

Ensure multi-region resources follow geographic compliance requirements.

```rego
package terraform.analysis

import input as tfplan

allowed_regions := {"us-east-1", "us-west-2", "eu-west-1", "eu-central-1"}
eu_only_regions := {"eu-west-1", "eu-central-1"}

deny contains msg if {
    region := tfplan.configuration.provider_config.aws.expressions.region.constant_value
    not allowed_regions[region]
    msg := sprintf("Region %v is not in approved regions list", [region])
}

# Ensure EU data stays in EU
deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type in {"aws_s3_bucket", "aws_rds_cluster", "aws_dynamodb_table"}
    r.change.actions[_] == "create"
    tags := object.get(r.change.after, "tags", {})
    tags.DataResidency == "EU"
    region := tfplan.configuration.provider_config.aws.expressions.region.constant_value
    not eu_only_regions[region]
    msg := sprintf("Resource %v with EU data residency requirement must be in EU region", [r.address])
}

# Require multi-region replication for critical resources
warn contains msg if {
    r := tfplan.resource_changes[_]
    r.type in {"aws_s3_bucket", "aws_dynamodb_table"}
    r.change.actions[_] == "create"
    tags := object.get(r.change.after, "tags", {})
    tags.Criticality == "high"
    not has_replication(r)
    msg := sprintf("Critical resource %v should have multi-region replication configured", [r.address])
}

has_replication(resource) if {
    resource.type == "aws_s3_bucket"
    resource.change.after.replication_configuration
}

has_replication(resource) if {
    resource.type == "aws_dynamodb_table"
    count(resource.change.after.replica) > 0
}
```

**Description**: Validates resources are deployed in approved regions and enforces data residency requirements with multi-region replication for critical resources.

---

## 20. TERRAFORM STATE BACKEND VALIDATION

Ensure Terraform state is stored securely with proper backend configuration.

```rego
package terraform.state

import input as tfplan

deny contains msg if {
    backend := tfplan.configuration.terraform.backend
    not backend
    msg := "Terraform must use remote state backend (S3, Terraform Cloud, etc.)"
}

deny contains msg if {
    backend := tfplan.configuration.terraform.backend.s3
    not backend.encrypt
    msg := "Terraform S3 backend must have encryption enabled"
}

deny contains msg if {
    backend := tfplan.configuration.terraform.backend.s3
    not backend.dynamodb_table
    msg := "Terraform S3 backend must use DynamoDB table for state locking"
}

# Ensure state bucket has versioning
deny contains msg if {
    backend := tfplan.configuration.terraform.backend.s3
    bucket := backend.bucket
    not state_bucket_has_versioning(bucket)
    msg := sprintf("State bucket %v must have versioning enabled", [bucket])
}

state_bucket_has_versioning(bucket_name) if {
    r := tfplan.resource_changes[_]
    r.type == "aws_s3_bucket_versioning"
    contains(r.change.after.bucket, bucket_name)
    r.change.after.versioning_configuration[_].status == "Enabled"
}
```

**Description**: Validates Terraform state backend configuration to ensure state is stored securely with encryption, locking, and versioning.

---

## 21. TERRAFORM PROVIDER VERSION CONSTRAINTS

Enforce provider version constraints to ensure reproducible infrastructure.

```rego
package terraform.providers

import input as tfplan

required_providers := {
    "aws": "~> 4.0",
    "azurerm": "~> 3.0",
    "google": "~> 4.0",
}

deny contains msg if {
    not tfplan.configuration.terraform.required_providers
    msg := "Terraform configuration must specify required_providers with version constraints"
}

deny contains msg if {
    provider_config := tfplan.configuration.terraform.required_providers
    some provider_name in object.keys(required_providers)
    not provider_config[provider_name]
    msg := sprintf("Required provider %v is not configured", [provider_name])
}

deny contains msg if {
    provider_config := tfplan.configuration.terraform.required_providers
    some provider_name, required_version in required_providers
    configured := provider_config[provider_name]
    configured_version := configured.version
    not configured_version
    msg := sprintf("Provider %v must specify version constraint", [provider_name])
}

# Ensure Terraform version is constrained
deny contains msg if {
    not tfplan.configuration.terraform.required_version
    msg := "Terraform configuration must specify required_version constraint"
}

warn contains msg if {
    version := tfplan.configuration.terraform.required_version
    not contains(version, "~>")
    not contains(version, ">=")
    msg := "Terraform version should use flexible constraint (~> or >=) rather than exact version"
}
```

**Description**: Ensures Terraform configurations specify provider and Terraform version constraints for reproducible and stable infrastructure deployments.

---

## Summary

These examples demonstrate comprehensive IaC validation covering:

- **Change Management**: Blast radius control, cost estimation
- **Security**: Encryption requirements, IAM least privilege, security group rules
- **Compliance**: Required tags, naming conventions, data residency
- **Operational Excellence**: Backup retention, monitoring, high availability
- **Resource Validation**: S3, RDS, Lambda, VPC, EBS, KMS configurations
- **Platform Controls**: State backend security, provider versioning, multi-region policies

All policies follow Rego best practices with:
- Clear violation messages
- Separation of concerns (helper rules)
- Proper handling of undefined values
- Support for both Terraform and CloudFormation
- Comprehensive coverage of AWS resources

These patterns can be adapted for other cloud providers (Azure, GCP) and extended to cover additional resource types and organizational requirements.
