# Policy Guide: Barbican (barbican)

This guide explains how to write policies for Barbican resources in OSPA.

## Service Overview

**Service Name:** `barbican`
**Display Name:** Barbican
**OpenStack Service Type:** key-manager

## Supported Resources


### Secret

**Resource Type:** `secret`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** status, age_gt, unused, exempt_names


### Container

**Resource Type:** `container`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** status, age_gt, unused, exempt_names


### Order

**Resource Type:** `order`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** status, age_gt, exempt_names



## OpenStack Security Guide Checklist

The following items from the OpenStack Security Guide apply to Barbican.
These are **configuration-level** checks that require manual verification on
the control plane (not API-auditable).

| ID | Description | Section | Manual |
|----|-------------|---------|--------|
- **Check-Key-Manager-01** | Ownership of config files set to root/barbican | secrets-management/checklist | Yes
- **Check-Key-Manager-02** | Strict permissions (640) on configuration files | secrets-management/checklist | Yes
- **Check-Key-Manager-03** | OpenStack Identity used for authentication | secrets-management/checklist | Yes
- **Check-Key-Manager-04** | TLS enabled for authentication | secrets-management/checklist | Yes



## Policy Structure

All policies for Barbican follow this structure:

```yaml
version: v1
defaults:
  workers: 50
  output: findings.json
policies:
  - barbican:
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
  description: Find inactive barbican resources
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
  description: Find unused barbican resources
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
  description: Audit barbican resources
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


### Secret Examples


#### Find Deactivated Secret Resources

```yaml
- name: find-deactivated-secrets
  description: Find deactivated secret resources
  resource: secret
  check:
    status: DEACTIVATED
  action: log
```

#### Find Old Secret Resources

```yaml
- name: find-old-secret
  description: Find secret resources older than 30 days
  resource: secret
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused Secret Resources

```yaml
- name: cleanup-unused-secret
  description: Delete unused secret resources
  resource: secret
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```


### Container Examples


#### Find Deactivated Container Resources

```yaml
- name: find-deactivated-containers
  description: Find deactivated container resources
  resource: container
  check:
    status: DEACTIVATED
  action: log
```

#### Find Old Container Resources

```yaml
- name: find-old-container
  description: Find container resources older than 30 days
  resource: container
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused Container Resources

```yaml
- name: cleanup-unused-container
  description: Delete unused container resources
  resource: container
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```


### Order Examples


#### Find Failed Order Resources

```yaml
- name: find-failed-orders
  description: Find order resources in a failed state
  resource: order
  check:
    status: FAILED
  action: log
```

#### Find Old Order Resources

```yaml
- name: find-old-order
  description: Find order resources older than 30 days
  resource: order
  check:
    age_gt: 30d
  action: log
```



## Complete Policy Example

Here's a complete policy file example for Barbican:

```yaml
version: v1
defaults:
  workers: 50
  output: findings.json
policies:
  - barbican:
    - name: audit-secret
      description: Audit secret resources
      resource: secret
      severity: medium
      category: hygiene
      check:
        status: ACTIVE
      action: log
    - name: cleanup-old-secret
      description: Find secret resources older than 90 days
      resource: secret
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
    - name: audit-container
      description: Audit container resources
      resource: container
      severity: medium
      category: hygiene
      check:
        status: ACTIVE
      action: log
    - name: cleanup-old-container
      description: Find container resources older than 90 days
      resource: container
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
    - name: audit-order
      description: Audit order resources
      resource: order
      severity: medium
      category: hygiene
      check:
        status: ACTIVE
      action: log
    - name: cleanup-old-order
      description: Find order resources older than 90 days
      resource: order
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
```

## OpenStack Documentation References

For more information about Barbican resources and their properties:

- **OpenStack Barbican API Documentation:** https://docs.openstack.org/api-ref/barbican/
- **Barbican Service Guide:** https://docs.openstack.org/barbican/latest/
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
- Ensure service name matches exactly: `barbican`
- Verify resource type is supported: `{secret Secrets [status age_gt unused exempt_names] [] [log delete tag] {false false false}}`, `{container Secret containers [status age_gt unused exempt_names] [] [log delete tag] {false false false}}`, `{order Orders [status age_gt exempt_names] [] [log delete tag] {false false false}}`
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
