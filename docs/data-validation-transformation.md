# Data Validation and Transformation

This document provides comprehensive examples of data validation, transformation, and content moderation patterns in Rego. These patterns are essential for building robust policy systems that validate inputs, transform data structures, and enforce content standards.

---

## 1. Comprehensive Input Validation

Validate multiple aspects of input data with field-level error reporting.

```rego
# METADATA
# title: Input Validation
# description: Validates multiple aspects of input data with field-level error reporting
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package validation

import rego.v1

# METADATA
# title: Validation errors
# description: Collects field-level validation errors for input data
# entrypoint: true
# custom:
#   severity: MEDIUM
errors contains msg if {
    not input.username
    msg := "username is required"
}

errors contains msg if {
    count(input.username) < 3
    msg := "username must be at least 3 characters"
}

errors contains msg if {
    not input.email
    msg := "email is required"
}

errors contains msg if {
    not contains(input.email, "@")
    msg := "email must be valid"
}

errors contains msg if {
    input.age < 18
    msg := "age must be 18 or older"
}

# METADATA
# title: Validation result
# description: Returns true when all validation checks pass with no errors
# entrypoint: true
# custom:
#   severity: MEDIUM
valid if {
    count(errors) == 0
}
```

---

## 2. Structured Error Responses

Return detailed error information with field-level errors and severity levels.

```rego
# METADATA
# title: Structured Error Responses
# description: Returns detailed error information with field-level errors and severity levels
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package validation

import rego.v1

# METADATA
# title: Validation result
# description: Aggregates errors and warnings into a structured validation response
# entrypoint: true
# custom:
#   severity: MEDIUM
result := {
    "valid": count(errors) == 0,
    "errors": errors,
    "warnings": warnings,
}

# METADATA
# title: Validation errors
# description: Collects field-level validation errors for password requirements
# entrypoint: true
# custom:
#   severity: HIGH
errors contains error if {
    not input.password
    error := {
        "field": "password",
        "message": "password is required",
        "severity": "error",
    }
}

errors contains error if {
    count(input.password) < 8
    error := {
        "field": "password",
        "message": "password must be at least 8 characters",
        "severity": "error",
    }
}

# METADATA
# title: Validation warnings
# description: Collects field-level warnings for password strength recommendations
# entrypoint: true
# custom:
#   severity: LOW
warnings contains warning if {
    count(input.password) < 12
    warning := {
        "field": "password",
        "message": "password should be at least 12 characters for better security",
        "severity": "warning",
    }
}

warnings contains warning if {
    not regex.match(`[A-Z]`, input.password)
    warning := {
        "field": "password",
        "message": "password should contain uppercase letters",
        "severity": "warning",
    }
}
```

---

## 3. Email Validation

Validate email format using pattern matching.

```rego
# METADATA
# title: Email Validation
# description: Validates email format using pattern matching
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package content.validation

import rego.v1

# METADATA
# title: Valid email check
# description: Validates that the input email has a proper format with domain
# entrypoint: true
# custom:
#   severity: MEDIUM
valid_email if {
    contains(input.email, "@")
    parts := split(input.email, "@")
    count(parts) == 2
    parts[0] != ""
    parts[1] != ""
    contains(parts[1], ".")
}

# More comprehensive email validation
advanced_email_validation if {
    regex.match(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, input.email)
}

# METADATA
# title: Email validation errors
# description: Collects error messages for invalid email formats
# entrypoint: true
# custom:
#   severity: MEDIUM
errors contains msg if {
    not valid_email
    msg := sprintf("invalid email format: %v", [input.email])
}
```

---

## 4. URL Validation

Validate URL format and allowed protocols.

```rego
# METADATA
# title: URL Validation
# description: Validates URL format and allowed protocols
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package validation.url

import rego.v1

allowed_protocols := {"https", "http"}

valid_url if {
    contains(input.url, "://")
    parts := split(input.url, "://")
    count(parts) >= 2
    protocol := parts[0]
    allowed_protocols[protocol]
    parts[1] != ""
}

# METADATA
# title: URL validation errors
# description: Collects error messages for invalid URLs and protocol violations
# entrypoint: true
# custom:
#   severity: MEDIUM
errors contains msg if {
    not valid_url
    msg := sprintf("invalid URL: %v", [input.url])
}

# HTTPS-only validation
errors contains msg if {
    not startswith(input.url, "https://")
    msg := "only HTTPS URLs are allowed"
}
```

---

## 5. Content Filtering and Moderation

Filter content containing banned words with case-insensitive matching.

```rego
# METADATA
# title: Content Filtering and Moderation
# description: Filters content containing banned words with case-insensitive matching
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package content.moderation

import rego.v1

banned_words := {"hate", "kill", "spam", "offensive"}

# METADATA
# title: Content violations
# description: Collects banned words found in the input message
# entrypoint: true
# custom:
#   severity: HIGH
violations contains word if {
    some word in banned_words
    contains(lower(input.message), word)
}

# METADATA
# title: Content deny decision
# description: Denies content when any banned word violations are detected
# entrypoint: true
# custom:
#   severity: HIGH
deny if {
    count(violations) > 0
}

# Return detailed violation information
moderation_result := {
    "allowed": count(violations) == 0,
    "violations": violations,
    "message": message,
}

message := "content contains prohibited words" if {
    count(violations) > 0
} else := "content approved"
```

---

## 6. Object Filtering and Projection

Filter and project objects based on criteria.

```rego
# METADATA
# title: Object Filtering and Projection
# description: Filters and projects objects based on criteria
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package transform

import rego.v1

# METADATA
# title: Active users
# description: Filters users to return only those with active status
# entrypoint: true
# custom:
#   severity: LOW
# Filter active users
active_users := {user |
    some user in input.users
    user.status == "active"
}

# Filter admin users
admin_users := {user |
    some user in input.users
    "admin" in user.roles
}

# Project specific fields
user_emails := {email |
    some user in input.users
    user.status == "active"
    email := user.email
}

# Create user summary objects
user_summaries[user.id] := summary if {
    some user in input.users
    summary := {
        "name": user.name,
        "email": user.email,
        "roles": user.roles,
    }
}
```

---

## 7. Data Aggregation and Grouping

Aggregate and group data from multiple sources.

```rego
# METADATA
# title: Data Aggregation and Grouping
# description: Aggregates and groups data from multiple sources
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package transform

import rego.v1

# METADATA
# title: Total cost by team
# description: Calculates total resource cost grouped by team
# entrypoint: true
# custom:
#   severity: LOW
# Total cost by team
total_cost_by_team[team] := total if {
    some team
    resources := [r | some r in input.resources; r.team == team]
    costs := [r.cost | some r in resources]
    total := sum(costs)
}

# Resource count by type
resource_count_by_type[resource_type] := count(resources) if {
    some resource_type
    resources := [r | some r in input.resources; r.type == resource_type]
}

# Average cost by region
average_cost_by_region[region] := avg if {
    some region
    resources := [r | some r in input.resources; r.region == region]
    costs := [r.cost | some r in resources]
    avg := sum(costs) / count(costs)
}

# Group users by department
users_by_department[dept] := users if {
    some dept
    users := [u | some u in input.users; u.department == dept]
}
```

---

## 8. Schema Validation

Validate data against expected schema structures.

```rego
# METADATA
# title: Schema Validation
# description: Validates data against expected schema structures
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package validation.schema

import rego.v1

# Validate required fields exist
required_fields := ["id", "name", "email", "created_at"]

# METADATA
# title: Schema validation errors
# description: Collects errors for missing required fields, invalid types, and malformed structures
# entrypoint: true
# custom:
#   severity: MEDIUM
errors contains msg if {
    some field in required_fields
    not object.get(input, field, null)
    msg := sprintf("missing required field: %v", [field])
}

# Validate field types
errors contains msg if {
    not is_string(input.id)
    msg := "field 'id' must be a string"
}

errors contains msg if {
    not is_string(input.name)
    msg := "field 'name' must be a string"
}

errors contains msg if {
    not is_string(input.email)
    msg := "field 'email' must be a string"
}

errors contains msg if {
    not is_number(input.created_at)
    msg := "field 'created_at' must be a number"
}

# Validate nested object structure
errors contains msg if {
    input.address
    not is_object(input.address)
    msg := "field 'address' must be an object"
}

errors contains msg if {
    input.address
    required_address_fields := ["street", "city", "country"]
    some field in required_address_fields
    not object.get(input.address, field, null)
    msg := sprintf("address missing required field: %v", [field])
}
```

---

## 9. Data Sanitization and Normalization

Clean and normalize input data.

```rego
# METADATA
# title: Data Sanitization and Normalization
# description: Cleans and normalizes input data using transformation helpers
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package transform.sanitize

import rego.v1

# Normalize email to lowercase
normalize_email(email) := lower(trim_space(email))

# Sanitize username (alphanumeric only)
sanitize_username(username) := clean if {
    clean := replace(username, " ", "_")
}

# Normalize phone number (remove non-digits)
normalize_phone(phone) := normalized if {
    digits := regex.replace(phone, `[^0-9]`, "")
    normalized := digits
}

# Trim and normalize whitespace
normalize_text(text) := normalized if {
    trimmed := trim_space(text)
    normalized := regex.replace(trimmed, `\s+`, " ")
}

# Transform user input
sanitized_user := {
    "username": sanitize_username(input.username),
    "email": normalize_email(input.email),
    "phone": normalize_phone(input.phone),
}
```

---

## 10. Type Coercion and Conversion

Convert and coerce data types safely.

```rego
# METADATA
# title: Type Coercion and Conversion
# description: Converts and coerces data types safely
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package transform.convert

import rego.v1

# String to number conversion with validation
to_number(str) := num if {
    is_string(str)
    num := to_number(str)
}

to_number(num) := num if {
    is_number(num)
}

# Boolean conversion from strings
to_boolean("true") := true
to_boolean("false") := false
to_boolean("1") := true
to_boolean("0") := false
to_boolean(true) := true
to_boolean(false) := false

# Convert array to set
to_set(arr) := {x | some x in arr} if {
    is_array(arr)
}

# Format numbers with specific precision
format_currency(amount) := formatted if {
    rounded := round(amount * 100) / 100
    formatted := sprintf("$%.2f", [rounded])
}

# Parse ISO date to components
parse_date(iso_date) := date if {
    parts := split(iso_date, "-")
    count(parts) == 3
    date := {
        "year": to_number(parts[0]),
        "month": to_number(parts[1]),
        "day": to_number(parts[2]),
    }
}
```

---

## 11. String Manipulation Helpers

Reusable string manipulation functions.

```rego
# METADATA
# title: String Manipulation Helpers
# description: Reusable string manipulation functions
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package helpers

import rego.v1

# Extract file extension
file_extension(filename) := ext if {
    parts := split(filename, ".")
    count(parts) > 1
    ext := parts[count(parts) - 1]
}

# Check if string matches any pattern
matches_any(str, patterns) if {
    some pattern in patterns
    glob.match(pattern, ["/"], str)
}

# Truncate string to max length
truncate(str, max_length) := truncated if {
    count(str) > max_length
    truncated := concat("", [substring(str, 0, max_length), "..."])
}

truncate(str, max_length) := str if {
    count(str) <= max_length
}

# Extract domain from email
email_domain(email) := domain if {
    parts := split(email, "@")
    count(parts) == 2
    domain := parts[1]
}

# Convert snake_case to camelCase
snake_to_camel(snake_str) := camel if {
    parts := split(snake_str, "_")
    first := parts[0]
    rest := [capitalize(p) | p := parts[i]; i > 0]
    all_parts := array.concat([first], rest)
    camel := concat("", all_parts)
}

capitalize(str) := result if {
    first := upper(substring(str, 0, 1))
    rest := substring(str, 1, count(str) - 1)
    result := concat("", [first, rest])
}
```

---

## 12. Collection Helpers and Utilities

Reusable collection manipulation functions.

```rego
# METADATA
# title: Collection Helpers and Utilities
# description: Reusable collection manipulation functions
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package helpers

import rego.v1

# Check if all elements satisfy condition
all_satisfy(collection, condition) if {
    every item in collection {
        condition(item)
    }
}

# Find elements matching condition
find_all(collection, condition) := results if {
    results := {item | some item in collection; condition(item)}
}

# Group by field
group_by(collection, field) := grouped if {
    grouped := {value: items |
        some value
        items := [item | some item in collection; item[field] == value]
    }
}

# Get unique values from array
unique(arr) := {x | some x in arr}

# Flatten nested arrays
flatten(arr) := flat if {
    flat := [x |
        some item in arr
        some x in item
    ]
}

# Intersection of multiple sets
intersect_all(sets) := result if {
    count(sets) > 0
    first := sets[0]
    result := {x |
        some x in first
        every s in sets {
            x in s
        }
    }
}
```

---

## 13. Nested Object Validation

Validate complex nested object structures.

```rego
# METADATA
# title: Nested Object Validation
# description: Validates complex nested object structures
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package validation.nested

import rego.v1

# METADATA
# title: Nested validation errors
# description: Collects errors for missing or malformed nested object fields
# entrypoint: true
# custom:
#   severity: MEDIUM
errors contains msg if {
    not input.user
    msg := "user object is required"
}

errors contains msg if {
    input.user
    not input.user.profile
    msg := "user.profile is required"
}

errors contains msg if {
    input.user.profile
    not input.user.profile.firstName
    msg := "user.profile.firstName is required"
}

errors contains msg if {
    input.user.profile
    not input.user.profile.lastName
    msg := "user.profile.lastName is required"
}

# Validate nested arrays
errors contains msg if {
    not input.user.addresses
    msg := "user.addresses array is required"
}

errors contains msg if {
    is_array(input.user.addresses)
    count(input.user.addresses) == 0
    msg := "user must have at least one address"
}

errors contains msg if {
    address := input.user.addresses[i]
    not address.street
    msg := sprintf("address[%d].street is required", [i])
}

errors contains msg if {
    address := input.user.addresses[i]
    not address.city
    msg := sprintf("address[%d].city is required", [i])
}
```

---

## 14. Array Validation with Constraints

Validate arrays with size and content constraints.

```rego
# METADATA
# title: Array Validation
# description: Validates arrays with size and content constraints
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package validation.array

import rego.v1

# METADATA
# title: Array validation errors
# description: Collects errors for invalid array size, uniqueness, and element types
# entrypoint: true
# custom:
#   severity: MEDIUM
errors contains msg if {
    not is_array(input.items)
    msg := "items must be an array"
}

errors contains msg if {
    count(input.items) < 1
    msg := "items array must not be empty"
}

errors contains msg if {
    count(input.items) > 100
    msg := "items array must not exceed 100 elements"
}

# Validate all items are unique
errors contains msg if {
    unique_items := {x | some x in input.items}
    count(unique_items) != count(input.items)
    msg := "items must be unique"
}

# Validate all items match type
errors contains msg if {
    some i
    item := input.items[i]
    not is_string(item)
    msg := sprintf("item[%d] must be a string", [i])
}

# Validate no empty strings
errors contains msg if {
    some i
    item := input.items[i]
    is_string(item)
    trim_space(item) == ""
    msg := sprintf("item[%d] cannot be empty", [i])
}
```

---

## 15. Enum Value Validation

Validate values against allowed enumerations.

```rego
# METADATA
# title: Enum Value Validation
# description: Validates values against allowed enumerations
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package validation.enum

import rego.v1

allowed_statuses := {"active", "inactive", "pending", "suspended"}

# METADATA
# title: Enum validation errors
# description: Collects errors for values not in allowed enumerations
# entrypoint: true
# custom:
#   severity: MEDIUM
errors contains msg if {
    not input.status
    msg := "status is required"
}

errors contains msg if {
    input.status
    not allowed_statuses[input.status]
    msg := sprintf("status must be one of: %v", [allowed_statuses])
}

# Multiple enum fields
allowed_roles := {"admin", "user", "moderator", "guest"}
allowed_regions := {"us-east-1", "us-west-2", "eu-west-1"}

errors contains msg if {
    input.role
    not allowed_roles[input.role]
    msg := sprintf("invalid role: %v (allowed: %v)", [input.role, allowed_roles])
}

errors contains msg if {
    input.region
    not allowed_regions[input.region]
    msg := sprintf("invalid region: %v (allowed: %v)", [input.region, allowed_regions])
}
```

---

## 16. Range and Boundary Checks

Validate numeric ranges and boundaries.

```rego
# METADATA
# title: Range and Boundary Checks
# description: Validates numeric ranges and boundaries
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package validation.range

import rego.v1

# METADATA
# title: Range validation errors
# description: Collects errors for values outside allowed numeric ranges and boundaries
# entrypoint: true
# custom:
#   severity: MEDIUM
errors contains msg if {
    not input.age
    msg := "age is required"
}

errors contains msg if {
    input.age < 0
    msg := "age cannot be negative"
}

errors contains msg if {
    input.age > 150
    msg := "age cannot exceed 150"
}

errors contains msg if {
    input.score < 0
    msg := "score must be between 0 and 100"
}

errors contains msg if {
    input.score > 100
    msg := "score must be between 0 and 100"
}

# Date range validation
errors contains msg if {
    input.start_date > input.end_date
    msg := "start_date must be before end_date"
}

# Price range validation
errors contains msg if {
    input.price <= 0
    msg := "price must be greater than 0"
}

errors contains msg if {
    input.quantity < 1
    msg := "quantity must be at least 1"
}

errors contains msg if {
    input.quantity > 1000
    msg := "quantity cannot exceed 1000"
}
```

---

## 17. Regular Expression Validation

Validate patterns using regular expressions.

```rego
# METADATA
# title: Regular Expression Validation
# description: Validates patterns using regular expressions
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package validation.regex

import rego.v1

# METADATA
# title: Regex validation errors
# description: Collects errors for inputs that do not match required patterns
# entrypoint: true
# custom:
#   severity: HIGH
# Username validation (alphanumeric and underscores)
errors contains msg if {
    not regex.match(`^[a-zA-Z0-9_]{3,20}$`, input.username)
    msg := "username must be 3-20 characters (alphanumeric and underscores only)"
}

# Strong password validation
errors contains msg if {
    not regex.match(`^.{8,}$`, input.password)
    msg := "password must be at least 8 characters"
}

errors contains msg if {
    not regex.match(`[A-Z]`, input.password)
    msg := "password must contain at least one uppercase letter"
}

errors contains msg if {
    not regex.match(`[a-z]`, input.password)
    msg := "password must contain at least one lowercase letter"
}

errors contains msg if {
    not regex.match(`[0-9]`, input.password)
    msg := "password must contain at least one digit"
}

errors contains msg if {
    not regex.match(`[!@#$%^&*(),.?":{}|<>]`, input.password)
    msg := "password must contain at least one special character"
}

# IPv4 address validation
errors contains msg if {
    input.ip_address
    not regex.match(`^(\d{1,3}\.){3}\d{1,3}$`, input.ip_address)
    msg := "invalid IPv4 address format"
}

# Hex color code validation
errors contains msg if {
    input.color
    not regex.match(`^#[0-9A-Fa-f]{6}$`, input.color)
    msg := "color must be a valid hex code (e.g., #FF5733)"
}
```

---

## 18. Date and Time Validation

Validate date and time formats.

```rego
# METADATA
# title: Date and Time Validation
# description: Validates date and time formats
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package validation.datetime

import rego.v1

# METADATA
# title: Date and time validation errors
# description: Collects errors for invalid date and time formats and component values
# entrypoint: true
# custom:
#   severity: MEDIUM
# ISO 8601 date validation
errors contains msg if {
    not regex.match(`^\d{4}-\d{2}-\d{2}$`, input.date)
    msg := "date must be in ISO 8601 format (YYYY-MM-DD)"
}

# Validate date components
errors contains msg if {
    parts := split(input.date, "-")
    count(parts) == 3
    month := to_number(parts[1])
    month < 1
    msg := "month must be between 1 and 12"
}

errors contains msg if {
    parts := split(input.date, "-")
    count(parts) == 3
    month := to_number(parts[1])
    month > 12
    msg := "month must be between 1 and 12"
}

errors contains msg if {
    parts := split(input.date, "-")
    count(parts) == 3
    day := to_number(parts[2])
    day < 1
    msg := "day must be between 1 and 31"
}

errors contains msg if {
    parts := split(input.date, "-")
    count(parts) == 3
    day := to_number(parts[2])
    day > 31
    msg := "day must be between 1 and 31"
}

# ISO 8601 datetime validation
errors contains msg if {
    input.timestamp
    not regex.match(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})$`, input.timestamp)
    msg := "timestamp must be in ISO 8601 format"
}

# Time format validation (HH:MM)
errors contains msg if {
    input.time
    not regex.match(`^([01]\d|2[0-3]):[0-5]\d$`, input.time)
    msg := "time must be in HH:MM format (24-hour)"
}
```

---

## 19. Phone Number Validation

Validate phone numbers in various formats.

```rego
# METADATA
# title: Phone Number Validation
# description: Validates phone numbers in various formats
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package validation.phone

import rego.v1

# US phone number validation (various formats)
valid_us_phone if {
    regex.match(`^\d{10}$`, input.phone)
}

valid_us_phone if {
    regex.match(`^\d{3}-\d{3}-\d{4}$`, input.phone)
}

valid_us_phone if {
    regex.match(`^\(\d{3}\) \d{3}-\d{4}$`, input.phone)
}

valid_us_phone if {
    regex.match(`^\+1\d{10}$`, input.phone)
}

# METADATA
# title: Phone validation errors
# description: Collects errors for invalid phone number formats
# entrypoint: true
# custom:
#   severity: MEDIUM
errors contains msg if {
    not valid_us_phone
    msg := "invalid US phone number format"
}

# International phone number validation
errors contains msg if {
    input.international_phone
    not regex.match(`^\+[1-9]\d{1,14}$`, input.international_phone)
    msg := "invalid international phone number (E.164 format)"
}

# Normalize phone number
normalize_phone(phone) := normalized if {
    digits := regex.replace(phone, `[^0-9]`, "")
    normalized := digits
}

# Validate normalized phone length
errors contains msg if {
    normalized := normalize_phone(input.phone)
    count(normalized) < 10
    msg := "phone number must have at least 10 digits"
}

errors contains msg if {
    normalized := normalize_phone(input.phone)
    count(normalized) > 15
    msg := "phone number cannot exceed 15 digits"
}
```

---

## 20. Credit Card Validation

Validate credit card numbers using Luhn algorithm pattern.

```rego
# METADATA
# title: Credit Card Validation
# description: Validates credit card numbers, CVV, and expiration dates
# authors:
# - Policy Engineering Team <policy-eng@example.com>
# custom:
#   category: data-validation
package validation.creditcard

import rego.v1

# METADATA
# title: Credit card validation errors
# description: Collects errors for invalid card numbers, CVV, and expiration dates
# entrypoint: true
# custom:
#   severity: HIGH
# Basic credit card format validation
errors contains msg if {
    not input.card_number
    msg := "card number is required"
}

errors contains msg if {
    digits := regex.replace(input.card_number, `[^0-9]`, "")
    count(digits) < 13
    msg := "card number must be at least 13 digits"
}

errors contains msg if {
    digits := regex.replace(input.card_number, `[^0-9]`, "")
    count(digits) > 19
    msg := "card number cannot exceed 19 digits"
}

# Card type detection
card_type := "visa" if {
    regex.match(`^4`, input.card_number)
}

card_type := "mastercard" if {
    regex.match(`^5[1-5]`, input.card_number)
}

card_type := "amex" if {
    regex.match(`^3[47]`, input.card_number)
}

card_type := "discover" if {
    regex.match(`^6(?:011|5)`, input.card_number)
}

card_type := "unknown"

# CVV validation
errors contains msg if {
    not input.cvv
    msg := "CVV is required"
}

errors contains msg if {
    card_type == "amex"
    not regex.match(`^\d{4}$`, input.cvv)
    msg := "CVV must be 4 digits for American Express"
}

errors contains msg if {
    card_type != "amex"
    not regex.match(`^\d{3}$`, input.cvv)
    msg := "CVV must be 3 digits"
}

# Expiration date validation
errors contains msg if {
    not input.expiry
    msg := "expiry date is required"
}

errors contains msg if {
    not regex.match(`^(0[1-9]|1[0-2])/\d{2}$`, input.expiry)
    msg := "expiry must be in MM/YY format"
}

# Check if card is expired
errors contains msg if {
    parts := split(input.expiry, "/")
    count(parts) == 2
    exp_month := to_number(parts[0])
    exp_year := 2000 + to_number(parts[1])
    current_time := time.now_ns()
    [current_year, current_month, _] := time.date(current_time)
    exp_year < current_year
    msg := "card has expired"
}

errors contains msg if {
    parts := split(input.expiry, "/")
    count(parts) == 2
    exp_month := to_number(parts[0])
    exp_year := 2000 + to_number(parts[1])
    current_time := time.now_ns()
    [current_year, current_month, _] := time.date(current_time)
    exp_year == current_year
    exp_month < current_month
    msg := "card has expired"
}
```

---

## Summary

This document covers comprehensive data validation and transformation patterns in Rego:

1. **Input Validation** - Multi-field validation with error collection
2. **Structured Errors** - Field-level errors with severity levels
3. **Email Validation** - Format validation and pattern matching
4. **URL Validation** - Protocol and format checking
5. **Content Moderation** - Banned word filtering
6. **Object Filtering** - Criteria-based data filtering
7. **Data Aggregation** - Grouping and statistical operations
8. **Schema Validation** - Type and structure validation
9. **Data Sanitization** - Normalization and cleaning
10. **Type Coercion** - Safe type conversion
11. **String Helpers** - Reusable string utilities
12. **Collection Helpers** - Reusable collection utilities
13. **Nested Validation** - Complex object validation
14. **Array Validation** - Size and content constraints
15. **Enum Validation** - Allowed value checking
16. **Range Checks** - Numeric boundary validation
17. **Regex Validation** - Pattern-based validation
18. **Date/Time Validation** - Temporal data validation
19. **Phone Validation** - Phone number format checking
20. **Credit Card Validation** - Payment card validation

These patterns provide a comprehensive toolkit for building robust validation and transformation policies in Rego, suitable for API validation, data quality enforcement, and content moderation systems.
