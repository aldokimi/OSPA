# Policy Guide: Keystone (keystone)

This guide explains how to write policies for Keystone resources in OSPA.

## Service Overview

**Service Name:** `keystone`
**Display Name:** Keystone
**OpenStack Service Type:** identity

## Supported Resources


### User

**Resource Type:** `user`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** status, age_gt, unused, exempt_names, password_expired, has_admin_role, mfa_enabled

#### Security & Domain Checks

| Check | Severity | Category | Type | Description |
|-------|----------|----------|------|-------------|
- **`password_expired`** | high | security | bool | User password has expired
- **`has_admin_role`** | high | security | bool | User has admin role assigned
- **`mfa_enabled`** | high | security | bool | User does not have MFA enabled


### Role

**Resource Type:** `role`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** age_gt, unused, exempt_names


### Project

**Resource Type:** `project`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** status, age_gt, unused, exempt_names


### Domain

**Resource Type:** `domain`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** status, age_gt, unused, exempt_names


### Group

**Resource Type:** `group`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** age_gt, unused, exempt_names


### Service

**Resource Type:** `service`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** status, age_gt, unused, exempt_names



## OpenStack Security Guide Checklist

The following items from the OpenStack Security Guide apply to Keystone.
These are **configuration-level** checks that require manual verification on
the control plane (not API-auditable).

| ID | Description | Section | Manual |
|----|-------------|---------|--------|
- **Check-Identity-01** | User/group ownership of config files set to keystone | identity/checklist | Yes
- **Check-Identity-02** | Strict permissions (640) on configuration files | identity/checklist | Yes
- **Check-Identity-03** | TLS enabled for Identity | identity/checklist | Yes
- **Check-Identity-05** | max_request_body_size set to default (114688) | identity/checklist | Yes
- **Check-Identity-06** | Admin token disabled | identity/checklist | Yes
- **Check-Identity-07** | insecure_debug set to false | identity/checklist | Yes
- **Check-Identity-08** | Fernet token provider used | identity/checklist | Yes



## Policy Structure

All policies for Keystone follow this structure:

```yaml
version: v1
defaults:
  workers: 50
  output: findings.json
policies:
  - keystone:
    - name: rule-name
      description: Rule description
      resource: <resource_type>
      severity: critical|high|medium|low
      category: security|compliance|cost|hygiene
      check:
        # Check conditions (see below)
      action: log|delete|tag
```

## Check Conditions

### Common Check Conditions

The following check conditions are available for most resources:

#### Status Check

Check resources by their status:

```yaml
check:
  status: active|inactive|available|unavailable|DOWN|UP
```

**Example:**
```yaml
- name: find-inactive-resources
  description: Find inactive keystone resources
  resource: <resource_type>
  check:
    status: inactive
  action: log
```

#### Age Check

Find resources older than a specified age:

```yaml
check:
  age_gt: 30d  # Options: 7d, 30d, 90d, 1h, 24h, etc.
```

**Supported units:**
- `d` or `day` or `days` - Days
- `h` or `hour` or `hours` - Hours
- `m` or `min` or `minute` or `minutes` - Minutes

**Example:**
```yaml
- name: find-old-resources
  description: Find resources older than 30 days
  resource: <resource_type>
  check:
    age_gt: 30d
  action: log
```

#### Unused Check

Find resources that are not being used:

```yaml
check:
  unused: true
```

**Example:**
```yaml
- name: find-unused-resources
  description: Find unused keystone resources
  resource: <resource_type>
  check:
    unused: true
  action: log
```

#### Exemptions

Exclude specific resources from checks:

```yaml
check:
  status: active
  exempt_names:
    - default
    - system-resource
```

**Example:**
```yaml
- name: find-active-except-default
  description: Find active resources except default ones
  resource: <resource_type>
  check:
    status: active
    exempt_names:
      - default
  action: log
```

## Actions

### Log Action

Log violations without taking any action:

```yaml
action: log
```

**Example:**
```yaml
- name: audit-resources
  description: Audit keystone resources
  resource: <resource_type>
  check:
    status: inactive
  action: log
```

### Delete Action

Delete non-compliant resources (use with caution):

```yaml
action: delete
```

**Example:**
```yaml
- name: cleanup-old-resources
  description: Delete resources older than 90 days
  resource: <resource_type>
  check:
    age_gt: 90d
  action: delete
```

**Note:** The `--fix` flag must be set when running the agent for delete actions to take effect.

### Tag Action

Tag non-compliant resources with metadata:

```yaml
action: tag
tag_name: audit-tag-name
action_tag_name: "Display Name for Tag"
```

**Example:**
```yaml
- name: tag-old-resources
  description: Tag resources older than 30 days
  resource: <resource_type>
  check:
    age_gt: 30d
  action: tag
  tag_name: audit-old-resource
  action_tag_name: "Old Resource"
```

## Resource-Specific Examples


### User Examples

#### Security Check Example

```yaml
- name: security-check-user-password_expired
  description: "User password has expired"
  resource: user
  severity: high
  category: security
  check:
    password_expired: true
  action: log
```


#### Find Disabled User Resources

```yaml
- name: find-disabled-user
  description: Find disabled user resources
  resource: user
  check:
    status: disabled
  action: log
```

#### Find Old User Resources

```yaml
- name: find-old-user
  description: Find user resources older than 30 days
  resource: user
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused User Resources

```yaml
- name: cleanup-unused-user
  description: Delete unused user resources
  resource: user
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```


### Role Examples


#### Find Old Role Resources

```yaml
- name: find-old-role
  description: Find role resources older than 30 days
  resource: role
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused Role Resources

```yaml
- name: cleanup-unused-role
  description: Delete unused role resources
  resource: role
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```


### Project Examples


#### Find Disabled Project Resources

```yaml
- name: find-disabled-project
  description: Find disabled project resources
  resource: project
  check:
    status: disabled
  action: log
```

#### Find Old Project Resources

```yaml
- name: find-old-project
  description: Find project resources older than 30 days
  resource: project
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused Project Resources

```yaml
- name: cleanup-unused-project
  description: Delete unused project resources
  resource: project
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```


### Domain Examples


#### Find Disabled Domain Resources

```yaml
- name: find-disabled-domain
  description: Find disabled domain resources
  resource: domain
  check:
    status: disabled
  action: log
```

#### Find Old Domain Resources

```yaml
- name: find-old-domain
  description: Find domain resources older than 30 days
  resource: domain
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused Domain Resources

```yaml
- name: cleanup-unused-domain
  description: Delete unused domain resources
  resource: domain
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```


### Group Examples


#### Find Old Group Resources

```yaml
- name: find-old-group
  description: Find group resources older than 30 days
  resource: group
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused Group Resources

```yaml
- name: cleanup-unused-group
  description: Delete unused group resources
  resource: group
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```


### Service Examples


#### Find Disabled Service Resources

```yaml
- name: find-disabled-service
  description: Find disabled service resources
  resource: service
  check:
    status: disabled
  action: log
```

#### Find Old Service Resources

```yaml
- name: find-old-service
  description: Find service resources older than 30 days
  resource: service
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused Service Resources

```yaml
- name: cleanup-unused-service
  description: Delete unused service resources
  resource: service
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```



## Complete Policy Example

Here's a complete policy file example for Keystone:

```yaml
version: v1
defaults:
  workers: 50
  output: findings.json
policies:
  - keystone:
    - name: audit-user
      description: Audit user resources
      resource: user
      severity: medium
      category: hygiene
      check:
        status: enabled
      action: log
    - name: cleanup-old-user
      description: Find user resources older than 90 days
      resource: user
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
    - name: audit-role
      description: Audit role resources
      resource: role
      severity: medium
      category: hygiene
      check:
        unused: true
      action: log
    - name: cleanup-old-role
      description: Find role resources older than 90 days
      resource: role
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
    - name: audit-project
      description: Audit project resources
      resource: project
      severity: medium
      category: hygiene
      check:
        status: enabled
      action: log
    - name: cleanup-old-project
      description: Find project resources older than 90 days
      resource: project
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
    - name: audit-domain
      description: Audit domain resources
      resource: domain
      severity: medium
      category: hygiene
      check:
        status: enabled
      action: log
    - name: cleanup-old-domain
      description: Find domain resources older than 90 days
      resource: domain
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
    - name: audit-group
      description: Audit group resources
      resource: group
      severity: medium
      category: hygiene
      check:
        unused: true
      action: log
    - name: cleanup-old-group
      description: Find group resources older than 90 days
      resource: group
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
    - name: audit-service
      description: Audit service resources
      resource: service
      severity: medium
      category: hygiene
      check:
        status: enabled
      action: log
    - name: cleanup-old-service
      description: Find service resources older than 90 days
      resource: service
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
```

## OpenStack Documentation References

For more information about Keystone resources and their properties:

- **OpenStack Keystone API Documentation:** https://docs.openstack.org/api-ref/keystone/
- **Keystone Service Guide:** https://docs.openstack.org/keystone/latest/
- **OpenStack Security Guide:** https://docs.openstack.org/security-guide/

## Testing Your Policy

1. **Validate the policy:**
   ```bash
   go run ./cmd/agent --cloud "$OS_CLOUD" --policy your-policy.yaml --out /dev/null
   ```

2. **Run in audit mode (safe):**
   ```bash
   go run ./cmd/agent --cloud "$OS_CLOUD" --policy your-policy.yaml --out findings.json
   ```

3. **Apply remediations (use with caution):**
   ```bash
   go run ./cmd/agent --cloud "$OS_CLOUD" --policy your-policy.yaml --out findings.json --fix
   ```

## Notes

- All check conditions are optional, but at least one should be specified
- Multiple check conditions are combined with AND logic (all must match)
- The `exempt_names` list allows you to exclude specific resources by name
- Age checks use the resource's `UpdatedAt` timestamp, falling back to `CreatedAt` if not available
- Status values are case-sensitive and should match OpenStack API responses exactly
- Use `severity` and `category` to classify findings for prioritization

## Troubleshooting

**Policy validation fails:**
- Ensure service name matches exactly: `keystone`
- Verify resource type is supported: `{user Users [status age_gt unused exempt_names password_expired has_admin_role mfa_enabled] [{password_expired bool User password has expired security high } {has_admin_role bool User has admin role assigned security high } {mfa_enabled bool User does not have MFA enabled security high }] [log delete tag] {false false false}}`, `{role Roles [age_gt unused exempt_names] [] [log delete tag] {false false false}}`, `{project Projects [status age_gt unused exempt_names] [] [log delete tag] {false false false}}`, `{domain Domains [status age_gt unused exempt_names] [] [log delete tag] {false false false}}`, `{group Groups [age_gt unused exempt_names] [] [log delete tag] {false false false}}`, `{service Services [status age_gt unused exempt_names] [] [log delete tag] {false false false}}`
- Check YAML syntax is correct

**No resources found:**
- Verify resources exist in your OpenStack project
- Use `--all-tenants` flag if resources are in other projects (requires admin)
- Check OpenStack API endpoints are accessible

**Actions not working:**
- Ensure `--fix` flag is set for delete/tag actions
- Verify you have permissions to modify resources
- Check action-specific requirements (e.g., `tag_name` for tag action)

## See Also

- [OSPA Development Guide](../../developer-guide/index.md)
- [OSPA Architecture Guide](../../developer-guide/architecture.md)
- [Example Policies](https://github.com/OpenStack-Policy-Agent/OSPA/blob/main/examples/policies.yaml)
