# Policy Guide: Glance (glance)

This guide explains how to write policies for Glance resources in OSPA.

## Service Overview

**Service Name:** `glance`
**Display Name:** Glance
**OpenStack Service Type:** image

## Supported Resources


### Image

**Resource Type:** `image`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** status, age_gt, unused, exempt_names, visibility

#### Security & Domain Checks

| Check | Severity | Category | Type | Description |
|-------|----------|----------|------|-------------|
- **`visibility`** | high | security | string | Image visibility (public images may expose sensitive data)


### Member

**Resource Type:** `member`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** status, age_gt, unused, exempt_names



## OpenStack Security Guide Checklist

The following items from the OpenStack Security Guide apply to Glance.
These are **configuration-level** checks that require manual verification on
the control plane (not API-auditable).

| ID | Description | Section | Manual |
|----|-------------|---------|--------|
- **Check-Image-01** | User/group ownership of config files set to root/glance | image-storage/checklist | Yes
- **Check-Image-02** | Strict permissions (640) on configuration files | image-storage/checklist | Yes
- **Check-Image-03** | Keystone used for authentication | image-storage/checklist | Yes
- **Check-Image-04** | TLS enabled for authentication | image-storage/checklist | Yes
- **Check-Image-05** | Masked port scans prevented (copy_from restricted) | image-storage/checklist | Yes



## Policy Structure

All policies for Glance follow this structure:

```yaml
version: v1
defaults:
  workers: 50
  output: findings.json
policies:
  - glance:
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
  description: Find inactive glance resources
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
  description: Find unused glance resources
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
  description: Audit glance resources
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


### Image Examples

#### Security Check Example

```yaml
- name: security-check-image-visibility
  description: "Image visibility (public images may expose sensitive data)"
  resource: image
  severity: high
  category: security
  check:
    visibility: "value"
  action: log
```


#### Find Inactive Image Resources

```yaml
- name: find-inactive-image
  description: Find inactive image resources
  resource: image
  check:
    status: inactive
  action: log
```

#### Find Old Image Resources

```yaml
- name: find-old-image
  description: Find image resources older than 30 days
  resource: image
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused Image Resources

```yaml
- name: cleanup-unused-image
  description: Delete unused image resources
  resource: image
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```


### Member Examples


#### Find Inactive Member Resources

```yaml
- name: find-inactive-member
  description: Find inactive member resources
  resource: member
  check:
    status: inactive
  action: log
```

#### Find Old Member Resources

```yaml
- name: find-old-member
  description: Find member resources older than 30 days
  resource: member
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused Member Resources

```yaml
- name: cleanup-unused-member
  description: Delete unused member resources
  resource: member
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```



## Complete Policy Example

Here's a complete policy file example for Glance:

```yaml
version: v1
defaults:
  workers: 50
  output: findings.json
policies:
  - glance:
    - name: audit-image
      description: Audit image resources
      resource: image
      severity: medium
      category: hygiene
      check:
        status: active
      action: log
    - name: cleanup-old-image
      description: Find image resources older than 90 days
      resource: image
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
    - name: audit-member
      description: Audit member resources
      resource: member
      severity: medium
      category: hygiene
      check:
        status: active
      action: log
    - name: cleanup-old-member
      description: Find member resources older than 90 days
      resource: member
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
```

## OpenStack Documentation References

For more information about Glance resources and their properties:

- **OpenStack Glance API Documentation:** https://docs.openstack.org/api-ref/glance/
- **Glance Service Guide:** https://docs.openstack.org/glance/latest/
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
- Ensure service name matches exactly: `glance`
- Verify resource type is supported: `{image Images [status age_gt unused exempt_names visibility] [{visibility string Image visibility (public images may expose sensitive data) security high }] [log delete tag] {false false false}}`, `{member Image members [status age_gt unused exempt_names] [] [log delete tag] {false false false}}`
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
