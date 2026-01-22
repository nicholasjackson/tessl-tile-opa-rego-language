# Network Security and Regulatory Compliance Policies

This document provides comprehensive examples of using Rego for network security policies and regulatory compliance validation. These patterns are essential for enforcing security controls, managing network access, and meeting regulatory requirements across cloud-native infrastructure.

---

## Table of Contents

1. [Network Security Policies](#network-security-policies)
2. [Regulatory Compliance](#regulatory-compliance)
3. [Encryption and Certificate Management](#encryption-and-certificate-management)
4. [Audit and Logging Requirements](#audit-and-logging-requirements)

---

## Network Security Policies

### 1. CIDR Range Validation and IP Allowlisting

Validates that IP addresses fall within approved CIDR ranges, commonly used for restricting access to internal networks or approved cloud regions.

```rego
package network.policies

# Allowed private network ranges
allowed_cidrs := [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
]

# Deny access from IPs outside allowed ranges
deny contains msg if {
    ip := input.source_ip
    not is_allowed_ip(ip)
    msg := sprintf("IP address %v is not in allowed CIDR ranges", [ip])
}

# Check if IP is within any allowed CIDR
is_allowed_ip(ip) if {
    some cidr in allowed_cidrs
    net.cidr_contains(cidr, ip)
}

# Validate multiple IPs against CIDR ranges
validate_ip_list contains result if {
    some ip in input.ip_addresses
    some cidr in allowed_cidrs
    net.cidr_contains(cidr, ip)
    result := {
        "ip": ip,
        "cidr": cidr,
        "allowed": true
    }
}
```

### 2. Egress Traffic Control and Domain Restrictions

Controls outbound network traffic to ensure services only communicate with approved external endpoints.

```rego
package network.egress

# Approved external domains
allowed_domains := {
    "api.github.com",
    "registry.npmjs.org",
    "*.googleapis.com",
    "*.amazonaws.com",
    "*.azure.com"
}

# Deny egress to unauthorized hosts
deny contains msg if {
    host := input.request.host
    not is_allowed_host(host)
    msg := sprintf("Egress to %v is not allowed", [host])
}

# Check if host matches any allowed domain pattern
is_allowed_host(host) if {
    some pattern in allowed_domains
    glob.match(pattern, ["."], host)
}

# Validate egress by protocol and port
deny contains msg if {
    input.request.protocol == "http"
    input.request.port == 80
    msg := "Unencrypted HTTP egress is not allowed"
}

# Allow only specific ports for specific domains
deny contains msg if {
    host := input.request.host
    port := input.request.port
    not valid_port_for_host(host, port)
    msg := sprintf("Port %v is not allowed for host %v", [port, host])
}

valid_port_for_host(host, port) if {
    glob.match("*.amazonaws.com", ["."], host)
    port in {443, 8443}
}
```

### 3. Network Segmentation Policies

Enforces network segmentation to isolate workloads based on sensitivity levels.

```rego
package network.segmentation

# Network segment definitions
segments := {
    "dmz": {
        "cidrs": ["10.0.1.0/24", "10.0.2.0/24"],
        "sensitivity": "public"
    },
    "application": {
        "cidrs": ["10.0.10.0/24", "10.0.11.0/24"],
        "sensitivity": "internal"
    },
    "database": {
        "cidrs": ["10.0.20.0/24"],
        "sensitivity": "confidential"
    }
}

# Deny cross-segment traffic unless explicitly allowed
deny contains msg if {
    source_segment := segment_for_ip(input.source_ip)
    dest_segment := segment_for_ip(input.destination_ip)
    source_segment != dest_segment
    not allowed_flow(source_segment, dest_segment)
    msg := sprintf("Traffic from %v segment to %v segment is not allowed", [source_segment, dest_segment])
}

# Determine which segment an IP belongs to
segment_for_ip(ip) := segment_name if {
    some segment_name, config in segments
    some cidr in config.cidrs
    net.cidr_contains(cidr, ip)
}

# Define allowed cross-segment flows
allowed_flow("dmz", "application")
allowed_flow("application", "database")
```

### 4. Firewall Rule Validation

Validates firewall rules to ensure they follow security best practices.

```rego
package network.firewall

# Deny overly permissive firewall rules
deny contains msg if {
    rule := input.firewall_rules[_]
    rule.source_range == "0.0.0.0/0"
    rule.action == "allow"
    sensitive_port(rule.port)
    msg := sprintf("Firewall rule %v allows access from anywhere to sensitive port %v", [rule.name, rule.port])
}

# Define sensitive ports
sensitive_port(port) if {
    port in {22, 3389, 1433, 3306, 5432, 6379, 27017}
}

# Require justification for broad access rules
deny contains msg if {
    rule := input.firewall_rules[_]
    rule.source_range == "0.0.0.0/0"
    not rule.justification
    msg := sprintf("Firewall rule %v allows broad access but lacks justification", [rule.name])
}

# Validate rule priority conflicts
deny contains msg if {
    rule1 := input.firewall_rules[i]
    rule2 := input.firewall_rules[j]
    i != j
    rule1.priority == rule2.priority
    msg := sprintf("Firewall rules %v and %v have conflicting priority %v", [rule1.name, rule2.name, rule1.priority])
}
```

### 5. VPN Access Policies

Controls VPN access based on user attributes and network requirements.

```rego
package network.vpn

import data.users

# Deny VPN access outside business hours for non-privileged users
deny contains msg if {
    not is_business_hours
    user := users[input.user_id]
    not user.privileged_access
    msg := "VPN access outside business hours requires privileged access"
}

is_business_hours if {
    [hour, _, _] := time.clock(time.now_ns())
    hour >= 8
    hour < 18
}

# Require MFA for VPN connections
deny contains msg if {
    not input.mfa_verified
    msg := "Multi-factor authentication is required for VPN access"
}

# Restrict VPN access by geographic location
deny contains msg if {
    location := input.connection_location
    not location in allowed_locations
    msg := sprintf("VPN access from location %v is not permitted", [location])
}

allowed_locations := {"US", "CA", "GB", "DE", "FR"}
```

### 6. Load Balancer Configuration Validation

Ensures load balancers are configured securely.

```rego
package network.loadbalancer

# Require HTTPS listeners
deny contains msg if {
    lb := input.load_balancer
    listener := lb.listeners[_]
    listener.protocol == "HTTP"
    listener.port != 80
    msg := sprintf("Load balancer %v has HTTP listener on non-standard port %v", [lb.name, listener.port])
}

# Enforce TLS version for HTTPS listeners
deny contains msg if {
    lb := input.load_balancer
    listener := lb.listeners[_]
    listener.protocol == "HTTPS"
    not valid_tls_version(listener.ssl_policy)
    msg := sprintf("Load balancer %v listener uses insecure TLS version", [lb.name])
}

valid_tls_version(policy) if {
    policy.min_tls_version in {"TLSv1.2", "TLSv1.3"}
}

# Require health checks
deny contains msg if {
    lb := input.load_balancer
    not lb.health_check
    msg := sprintf("Load balancer %v must have health checks configured", [lb.name])
}
```

### 7. DNS Security Policies

Validates DNS configurations to prevent common security issues.

```rego
package network.dns

# Prevent DNS zone transfers to unauthorized servers
deny contains msg if {
    zone := input.dns_zone
    transfer := zone.zone_transfers[_]
    not is_authorized_server(transfer.server)
    msg := sprintf("DNS zone %v allows transfers to unauthorized server %v", [zone.name, transfer.server])
}

is_authorized_server(server) if {
    authorized_servers := {"10.0.1.10", "10.0.1.11"}
    server in authorized_servers
}

# Require DNSSEC for public zones
deny contains msg if {
    zone := input.dns_zone
    zone.visibility == "public"
    not zone.dnssec_enabled
    msg := sprintf("Public DNS zone %v must have DNSSEC enabled", [zone.name])
}

# Validate DNS record patterns
deny contains msg if {
    zone := input.dns_zone
    record := zone.records[_]
    record.type == "A"
    not valid_ip_format(record.value)
    msg := sprintf("DNS A record for %v has invalid IP format", [record.name])
}

valid_ip_format(ip) if {
    parts := split(ip, ".")
    count(parts) == 4
}
```

### 8. Zero-Trust Network Policies

Implements zero-trust network access principles.

```rego
package network.zerotrust

# Deny all traffic by default
default allow := false

# Allow only authenticated and authorized requests
allow if {
    valid_identity
    valid_device
    valid_authorization
}

valid_identity if {
    input.identity.verified
    input.identity.mfa_verified
    not is_expired(input.identity.token_expiry)
}

valid_device if {
    input.device.registered
    input.device.compliant
    input.device.last_scan_days < 7
}

valid_authorization if {
    some permission in input.identity.permissions
    permission.resource == input.requested_resource
    permission.action == input.requested_action
}

is_expired(expiry_time) if {
    time.now_ns() > expiry_time
}
```

### 9. Service Mesh Security Policies

Enforces security policies in service mesh environments.

```rego
package network.servicemesh

# Require mTLS for inter-service communication
deny contains msg if {
    connection := input.connection
    connection.source_service != "ingress-gateway"
    connection.destination_service != "egress-gateway"
    not connection.mtls_enabled
    msg := sprintf("Connection from %v to %v must use mTLS", [connection.source_service, connection.destination_service])
}

# Validate service identity
deny contains msg if {
    connection := input.connection
    not valid_service_identity(connection.source_identity)
    msg := sprintf("Invalid service identity: %v", [connection.source_identity])
}

valid_service_identity(identity) if {
    startswith(identity, "spiffe://")
    contains(identity, "/ns/")
    contains(identity, "/sa/")
}

# Enforce authorization policies
deny contains msg if {
    connection := input.connection
    not is_authorized_connection(connection.source_service, connection.destination_service)
    msg := sprintf("Service %v is not authorized to access %v", [connection.source_service, connection.destination_service])
}

is_authorized_connection(source, destination) if {
    policy := data.service_mesh.policies[destination]
    source in policy.allowed_sources
}
```

---

## Regulatory Compliance

### 10. PCI-DSS Compliance - Encryption Requirements

Validates that systems handling payment card data meet PCI-DSS encryption requirements.

```rego
package compliance.pci.encryption

# Require encryption for databases storing cardholder data
deny contains msg if {
    resource := input.resources[_]
    resource.type == "database"
    resource.stores_cardholder_data
    not resource.encrypted_at_rest
    msg := sprintf("Database %v stores cardholder data but is not encrypted (PCI-DSS Req 3.4)", [resource.id])
}

# Require strong encryption algorithms
deny contains msg if {
    resource := input.resources[_]
    resource.encrypted_at_rest
    not valid_encryption_algorithm(resource.encryption_algorithm)
    msg := sprintf("Resource %v uses weak encryption algorithm %v (PCI-DSS Req 3.5)", [resource.id, resource.encryption_algorithm])
}

valid_encryption_algorithm(algorithm) if {
    algorithm in {"AES-256", "AES-256-GCM", "RSA-2048", "RSA-4096"}
}

# Require encryption in transit
deny contains msg if {
    connection := input.connections[_]
    connection.transmits_cardholder_data
    not connection.encrypted_in_transit
    msg := sprintf("Connection %v transmits cardholder data without encryption (PCI-DSS Req 4.1)", [connection.id])
}
```

### 11. PCI-DSS Compliance - Logging and Monitoring

Ensures audit logging is enabled for systems in PCI-DSS scope.

```rego
package compliance.pci.logging

# Require audit logging for all PCI-relevant systems
deny contains msg if {
    resource := input.resources[_]
    resource.pci_scope
    not resource.audit_logging_enabled
    msg := sprintf("Resource %v is in PCI scope but lacks audit logging (PCI-DSS Req 10.1)", [resource.id])
}

# Validate log retention period
deny contains msg if {
    resource := input.resources[_]
    resource.pci_scope
    resource.log_retention_days < 365
    msg := sprintf("Resource %v has insufficient log retention: %v days (PCI-DSS Req 10.7)", [resource.id, resource.log_retention_days])
}

# Require logging of authentication attempts
deny contains msg if {
    system := input.systems[_]
    system.handles_authentication
    not logs_authentication_events(system)
    msg := sprintf("System %v must log authentication attempts (PCI-DSS Req 10.2.4)", [system.id])
}

logs_authentication_events(system) if {
    "authentication" in system.logged_event_types
}
```

### 12. PCI-DSS Compliance - Access Control

Validates access control mechanisms meet PCI-DSS requirements.

```rego
package compliance.pci.access

# Require unique user IDs
deny contains msg if {
    user := input.users[_]
    count([u | u := input.users[_]; u.user_id == user.user_id]) > 1
    msg := sprintf("Multiple users share user ID %v (PCI-DSS Req 8.1)", [user.user_id])
}

# Require password complexity
deny contains msg if {
    user := input.users[_]
    user.has_password
    not meets_password_requirements(user.password_policy)
    msg := sprintf("User %v password policy does not meet requirements (PCI-DSS Req 8.2.3)", [user.user_id])
}

meets_password_requirements(policy) if {
    policy.min_length >= 7
    policy.requires_uppercase
    policy.requires_lowercase
    policy.requires_numeric
}

# Require MFA for remote access
deny contains msg if {
    access := input.access_requests[_]
    access.access_type == "remote"
    access.target_scope == "cardholder_data_environment"
    not access.mfa_enabled
    msg := sprintf("Remote access to CDE requires MFA (PCI-DSS Req 8.3)", [access.user])
}
```

### 13. GDPR Compliance - Data Protection

Ensures compliance with GDPR data protection requirements.

```rego
package compliance.gdpr.protection

# Require encryption for personal data
deny contains msg if {
    resource := input.resources[_]
    resource.stores_personal_data
    not resource.encrypted
    msg := sprintf("Resource %v stores personal data without encryption (GDPR Art. 32)", [resource.id])
}

# Validate data minimization
deny contains msg if {
    collection := input.data_collections[_]
    field := collection.fields[_]
    field.data_category == "personal"
    not field.necessary_for_purpose
    msg := sprintf("Collection %v includes unnecessary personal data field %v (GDPR Art. 5(1)(c))", [collection.name, field.name])
}

# Require data retention policies
deny contains msg if {
    resource := input.resources[_]
    resource.stores_personal_data
    not resource.retention_policy
    msg := sprintf("Resource %v lacks data retention policy (GDPR Art. 5(1)(e))", [resource.id])
}

# Validate consent mechanism
deny contains msg if {
    processing := input.data_processing[_]
    processing.legal_basis == "consent"
    not valid_consent(processing.consent_mechanism)
    msg := sprintf("Processing %v has invalid consent mechanism (GDPR Art. 7)", [processing.id])
}

valid_consent(mechanism) if {
    mechanism.freely_given
    mechanism.specific
    mechanism.informed
    mechanism.unambiguous
}
```

### 14. GDPR Compliance - Data Subject Rights

Implements controls to support GDPR data subject rights.

```rego
package compliance.gdpr.rights

# Require data subject access request (DSAR) capability
deny contains msg if {
    system := input.systems[_]
    system.processes_personal_data
    not system.supports_dsar
    msg := sprintf("System %v must support data subject access requests (GDPR Art. 15)", [system.id])
}

# Validate right to erasure implementation
deny contains msg if {
    system := input.systems[_]
    system.processes_personal_data
    not system.supports_erasure
    not has_valid_retention_justification(system)
    msg := sprintf("System %v must support right to erasure (GDPR Art. 17)", [system.id])
}

has_valid_retention_justification(system) if {
    system.retention_justification in {
        "legal_obligation",
        "public_interest",
        "legal_claims"
    }
}

# Require data portability for automated processing
deny contains msg if {
    processing := input.data_processing[_]
    processing.automated
    processing.legal_basis == "consent"
    not processing.supports_portability
    msg := sprintf("Processing %v must support data portability (GDPR Art. 20)", [processing.id])
}
```

### 15. HIPAA Compliance - PHI Protection

Validates protection of Protected Health Information under HIPAA.

```rego
package compliance.hipaa.phi

# Require encryption for PHI at rest
deny contains msg if {
    resource := input.resources[_]
    resource.contains_phi
    not resource.encrypted_at_rest
    msg := sprintf("Resource %v contains PHI but is not encrypted (HIPAA §164.312(a)(2)(iv))", [resource.id])
}

# Require encryption for PHI in transit
deny contains msg if {
    transmission := input.transmissions[_]
    transmission.contains_phi
    not transmission.encrypted
    msg := sprintf("Transmission %v contains PHI without encryption (HIPAA §164.312(e)(1))", [transmission.id])
}

# Validate access controls for PHI
deny contains msg if {
    resource := input.resources[_]
    resource.contains_phi
    not resource.access_controls.role_based
    msg := sprintf("Resource %v with PHI lacks role-based access controls (HIPAA §164.308(a)(4))", [resource.id])
}

# Require audit logs for PHI access
deny contains msg if {
    resource := input.resources[_]
    resource.contains_phi
    not resource.audit_logging
    msg := sprintf("Resource %v with PHI must have audit logging (HIPAA §164.312(b))", [resource.id])
}

# Validate minimum necessary principle
deny contains msg if {
    access := input.access_grants[_]
    access.resource_contains_phi
    not is_minimum_necessary(access)
    msg := sprintf("Access grant %v violates minimum necessary principle (HIPAA §164.502(b))", [access.id])
}

is_minimum_necessary(access) if {
    access.justified_by_role
    access.limited_fields
    access.time_limited
}
```

### 16. Data Residency Requirements

Ensures data stays within required geographic boundaries for compliance.

```rego
package compliance.data_residency

# Define region requirements by data classification
region_requirements := {
    "eu_customer_data": {"allowed_regions": {"eu-west-1", "eu-central-1", "eu-north-1"}},
    "us_customer_data": {"allowed_regions": {"us-east-1", "us-west-2"}},
    "global_public_data": {"allowed_regions": "*"}
}

# Deny resources storing data outside allowed regions
deny contains msg if {
    resource := input.resources[_]
    classification := resource.data_classification
    requirements := region_requirements[classification]
    requirements.allowed_regions != "*"
    not resource.region in requirements.allowed_regions
    msg := sprintf("Resource %v with %v must be in regions %v, found in %v", [
        resource.id,
        classification,
        requirements.allowed_regions,
        resource.region
    ])
}

# Validate cross-region replication
deny contains msg if {
    resource := input.resources[_]
    resource.replication_enabled
    replica_region := resource.replica_regions[_]
    classification := resource.data_classification
    requirements := region_requirements[classification]
    requirements.allowed_regions != "*"
    not replica_region in requirements.allowed_regions
    msg := sprintf("Resource %v replicates %v to unauthorized region %v", [
        resource.id,
        classification,
        replica_region
    ])
}

# Prevent data transfer outside allowed regions
deny contains msg if {
    transfer := input.data_transfers[_]
    classification := transfer.data_classification
    requirements := region_requirements[classification]
    requirements.allowed_regions != "*"
    not transfer.destination_region in requirements.allowed_regions
    msg := sprintf("Data transfer %v moves %v to unauthorized region %v", [
        transfer.id,
        classification,
        transfer.destination_region
    ])
}
```

### 17. SOC 2 Compliance Controls

Implements SOC 2 Trust Service Criteria controls.

```rego
package compliance.soc2

# CC6.1 - Logical Access Controls
deny contains msg if {
    system := input.systems[_]
    system.criticality == "high"
    not system.requires_authentication
    msg := sprintf("System %v lacks authentication requirements (SOC 2 CC6.1)", [system.id])
}

# CC6.6 - Encryption
deny contains msg if {
    data_store := input.data_stores[_]
    data_store.sensitivity in {"confidential", "restricted"}
    not data_store.encrypted_at_rest
    msg := sprintf("Sensitive data store %v is not encrypted (SOC 2 CC6.6)", [data_store.id])
}

# CC6.7 - Transmission Security
deny contains msg if {
    connection := input.connections[_]
    connection.data_classification != "public"
    not connection.encrypted
    msg := sprintf("Non-public data connection %v is not encrypted (SOC 2 CC6.7)", [connection.id])
}

# CC7.2 - System Monitoring
deny contains msg if {
    system := input.systems[_]
    not system.monitoring_enabled
    msg := sprintf("System %v lacks monitoring (SOC 2 CC7.2)", [system.id])
}

# CC7.3 - Change Management
deny contains msg if {
    change := input.changes[_]
    change.impact == "high"
    not change.approved
    msg := sprintf("High-impact change %v is not approved (SOC 2 CC7.3)", [change.id])
}

# A1.2 - Availability Monitoring
deny contains msg if {
    service := input.services[_]
    service.sla_required
    not service.availability_monitoring
    msg := sprintf("Service %v with SLA lacks availability monitoring (SOC 2 A1.2)", [service.id])
}
```

---

## Encryption and Certificate Management

### 18. TLS/SSL Version Enforcement

Enforces use of secure TLS/SSL versions and cipher suites.

```rego
package security.tls

# Deny use of deprecated TLS versions
deny contains msg if {
    config := input.tls_config
    config.min_version in {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
    msg := sprintf("TLS configuration uses deprecated version %v, minimum should be TLSv1.2", [config.min_version])
}

# Require strong cipher suites
deny contains msg if {
    config := input.tls_config
    cipher := config.cipher_suites[_]
    is_weak_cipher(cipher)
    msg := sprintf("Weak cipher suite detected: %v", [cipher])
}

is_weak_cipher(cipher) if {
    weak_ciphers := {
        "TLS_RSA_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA"
    }
    cipher in weak_ciphers
}

# Require perfect forward secrecy
deny contains msg if {
    config := input.tls_config
    some cipher in config.cipher_suites
    not supports_pfs(cipher)
    msg := sprintf("Cipher suite %v does not support Perfect Forward Secrecy", [cipher])
}

supports_pfs(cipher) if {
    contains(cipher, "ECDHE")
}

supports_pfs(cipher) if {
    contains(cipher, "DHE")
}
```

### 19. Certificate Validation Policies

Validates SSL/TLS certificates meet security requirements.

```rego
package security.certificates

# Require valid certificate expiry
deny contains msg if {
    cert := input.certificates[_]
    is_expired(cert.not_after)
    msg := sprintf("Certificate %v has expired", [cert.common_name])
}

deny contains msg if {
    cert := input.certificates[_]
    expires_soon(cert.not_after, 30)
    msg := sprintf("Certificate %v expires within 30 days", [cert.common_name])
}

is_expired(not_after) if {
    expiry := time.parse_rfc3339_ns(not_after)
    expiry < time.now_ns()
}

expires_soon(not_after, days) if {
    expiry := time.parse_rfc3339_ns(not_after)
    threshold := time.now_ns() + (days * 24 * 60 * 60 * 1000000000)
    expiry < threshold
}

# Require strong key sizes
deny contains msg if {
    cert := input.certificates[_]
    cert.key_algorithm == "RSA"
    cert.key_size < 2048
    msg := sprintf("Certificate %v uses RSA key size %v, minimum is 2048", [cert.common_name, cert.key_size])
}

deny contains msg if {
    cert := input.certificates[_]
    cert.key_algorithm == "EC"
    cert.key_size < 256
    msg := sprintf("Certificate %v uses EC key size %v, minimum is 256", [cert.common_name, cert.key_size])
}

# Validate certificate chain
deny contains msg if {
    cert := input.certificates[_]
    not cert.chain_valid
    msg := sprintf("Certificate %v has invalid chain", [cert.common_name])
}

# Require certificates from trusted CAs
deny contains msg if {
    cert := input.certificates[_]
    not is_trusted_ca(cert.issuer)
    msg := sprintf("Certificate %v issued by untrusted CA: %v", [cert.common_name, cert.issuer])
}

is_trusted_ca(issuer) if {
    trusted_cas := {
        "DigiCert",
        "Let's Encrypt",
        "Amazon",
        "Microsoft"
    }
    some ca in trusted_cas
    contains(issuer, ca)
}
```

### 20. Mutual TLS (mTLS) Requirements

Enforces mutual TLS authentication for service-to-service communication.

```rego
package security.mtls

# Require mTLS for internal service communication
deny contains msg if {
    connection := input.connections[_]
    connection.source_type == "service"
    connection.destination_type == "service"
    not connection.mtls_enabled
    msg := sprintf("Service-to-service connection from %v to %v must use mTLS", [
        connection.source,
        connection.destination
    ])
}

# Validate client certificate is presented
deny contains msg if {
    connection := input.connections[_]
    connection.mtls_enabled
    not connection.client_cert_presented
    msg := sprintf("mTLS connection from %v missing client certificate", [connection.source])
}

# Require certificate validation
deny contains msg if {
    connection := input.connections[_]
    connection.mtls_enabled
    not connection.verify_client_cert
    msg := sprintf("mTLS connection from %v does not verify client certificate", [connection.source])
}

# Validate certificate-based authorization
deny contains msg if {
    connection := input.connections[_]
    connection.mtls_enabled
    not has_valid_spiffe_id(connection.client_cert_subject)
    msg := sprintf("Client certificate for %v lacks valid SPIFFE ID", [connection.source])
}

has_valid_spiffe_id(subject) if {
    startswith(subject, "spiffe://")
}

# Require certificate rotation policy
deny contains msg if {
    service := input.services[_]
    service.uses_mtls
    not service.cert_rotation_policy
    msg := sprintf("Service %v uses mTLS but lacks certificate rotation policy", [service.name])
}

deny contains msg if {
    service := input.services[_]
    service.cert_rotation_policy
    service.cert_rotation_days > 90
    msg := sprintf("Service %v certificate rotation period %v days exceeds maximum of 90", [
        service.name,
        service.cert_rotation_days
    ])
}
```

---

## Audit and Logging Requirements

### 21. Audit Logging Requirements

Ensures comprehensive audit logging for security and compliance.

```rego
package security.audit

# Require audit logging for sensitive operations
deny contains msg if {
    operation := input.operations[_]
    is_sensitive_operation(operation.type)
    not operation.audit_logged
    msg := sprintf("Sensitive operation %v must be audit logged", [operation.type])
}

is_sensitive_operation(op_type) if {
    op_type in {
        "user_login",
        "user_logout",
        "permission_change",
        "data_access",
        "data_modification",
        "configuration_change",
        "security_event"
    }
}

# Validate log retention periods
deny contains msg if {
    system := input.systems[_]
    system.audit_logging_enabled
    system.log_retention_days < minimum_retention_days(system.compliance_scope)
    msg := sprintf("System %v log retention %v days is below minimum for %v compliance", [
        system.id,
        system.log_retention_days,
        system.compliance_scope
    ])
}

minimum_retention_days(scope) := 365 if {
    scope in {"pci-dss", "sox"}
}

minimum_retention_days(scope) := 180 if {
    scope == "hipaa"
}

minimum_retention_days(scope) := 90 if {
    scope == "default"
}

# Require log integrity protection
deny contains msg if {
    log_config := input.log_configuration
    not log_config.integrity_protection
    msg := "Audit logs must have integrity protection enabled"
}

# Validate log fields
deny contains msg if {
    log_entry := input.log_entries[_]
    not has_required_fields(log_entry)
    msg := sprintf("Log entry missing required fields: %v", [log_entry.id])
}

has_required_fields(entry) if {
    entry.timestamp
    entry.user
    entry.action
    entry.resource
    entry.result
}

# Require centralized logging
deny contains msg if {
    system := input.systems[_]
    system.generates_audit_logs
    not system.centralized_logging
    msg := sprintf("System %v must send audit logs to central logging", [system.id])
}
```

---

## Summary

This document provides 21 comprehensive examples covering:

**Network Security:**
- CIDR range validation and IP allowlisting
- Egress traffic control and domain restrictions
- Network segmentation policies
- Firewall rule validation
- VPN access policies
- Load balancer security
- DNS security
- Zero-trust architecture
- Service mesh security

**Regulatory Compliance:**
- PCI-DSS (encryption, logging, access control)
- GDPR (data protection, subject rights)
- HIPAA (PHI protection)
- Data residency requirements
- SOC 2 controls

**Encryption & Certificates:**
- TLS/SSL version enforcement
- Certificate validation
- Mutual TLS (mTLS)

**Audit & Logging:**
- Comprehensive audit logging requirements

These examples demonstrate production-ready patterns for implementing security policies and regulatory compliance validation using Rego. Each policy includes detailed validation logic, clear error messages, and follows Rego best practices for maintainability and performance.
