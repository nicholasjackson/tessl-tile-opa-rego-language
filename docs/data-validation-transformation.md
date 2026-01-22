# Data Validation and Transformation

This document provides comprehensive examples of data validation, transformation, and content moderation patterns in Rego. These patterns are essential for building robust policy systems that validate inputs, transform data structures, and enforce content standards.

---

## 1. Comprehensive Input Validation

Validate multiple aspects of input data with field-level error reporting.

```rego
package validation

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

valid if {
    count(errors) == 0
}
```

---

## 2. Structured Error Responses

Return detailed error information with field-level errors and severity levels.

```rego
package validation

result := {
    "valid": count(errors) == 0,
    "errors": errors,
    "warnings": warnings,
}

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
package content.validation

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

errors contains msg if {
    not valid_email
    msg := sprintf("invalid email format: %v", [input.email])
}
```

---

## 4. URL Validation

Validate URL format and allowed protocols.

```rego
package validation.url

allowed_protocols := {"https", "http"}

valid_url if {
    contains(input.url, "://")
    parts := split(input.url, "://")
    count(parts) >= 2
    protocol := parts[0]
    allowed_protocols[protocol]
    parts[1] != ""
}

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
package content.moderation

banned_words := {"hate", "kill", "spam", "offensive"}

violations contains word if {
    some word in banned_words
    contains(lower(input.message), word)
}

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
package transform

# Filter active users
active_users := {user |
    user := input.users[_]
    user.status == "active"
}

# Filter admin users
admin_users := {user |
    user := input.users[_]
    "admin" in user.roles
}

# Project specific fields
user_emails := {email |
    user := input.users[_]
    user.status == "active"
    email := user.email
}

# Create user summary objects
user_summaries[user.id] := summary if {
    user := input.users[_]
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
package transform

# Total cost by team
total_cost_by_team[team] := total if {
    some team
    resources := [r | r := input.resources[_]; r.team == team]
    costs := [r.cost | r := resources[_]]
    total := sum(costs)
}

# Resource count by type
resource_count_by_type[resource_type] := count(resources) if {
    some resource_type
    resources := [r | r := input.resources[_]; r.type == resource_type]
}

# Average cost by region
average_cost_by_region[region] := avg if {
    some region
    resources := [r | r := input.resources[_]; r.region == region]
    costs := [r.cost | r := resources[_]]
    avg := sum(costs) / count(costs)
}

# Group users by department
users_by_department[dept] := users if {
    some dept
    users := [u | u := input.users[_]; u.department == dept]
}
```

---

## 8. Schema Validation

Validate data against expected schema structures.

```rego
package validation.schema

# Validate required fields exist
required_fields := ["id", "name", "email", "created_at"]

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
package transform.sanitize

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
package transform.convert

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
to_set(arr) := {x | x := arr[_]} if {
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
package helpers

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
package helpers

# Check if all elements satisfy condition
all_satisfy(collection, condition) if {
    every item in collection {
        condition(item)
    }
}

# Find elements matching condition
find_all(collection, condition) := results if {
    results := {item | item := collection[_]; condition(item)}
}

# Group by field
group_by(collection, field) := grouped if {
    grouped := {value: items |
        some value
        items := [item | item := collection[_]; item[field] == value]
    }
}

# Get unique values from array
unique(arr) := {x | x := arr[_]}

# Flatten nested arrays
flatten(arr) := flat if {
    flat := [x |
        some item in arr
        x := item[_]
    ]
}

# Intersection of multiple sets
intersect_all(sets) := result if {
    count(sets) > 0
    first := sets[0]
    result := {x |
        x := first[_]
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
package validation.nested

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
package validation.array

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
    unique_items := {x | x := input.items[_]}
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
package validation.enum

allowed_statuses := {"active", "inactive", "pending", "suspended"}

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
package validation.range

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
package validation.regex

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
package validation.datetime

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
package validation.phone

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
package validation.creditcard

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
