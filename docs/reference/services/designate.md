# Policy Guide: Designate (designate)

This guide explains how to write policies for Designate resources in OSPA.

## Service Overview

**Service Name:** `designate`
**Display Name:** Designate
**OpenStack Service Type:** dns

## Supported Resources


### Zone

**Resource Type:** `zone`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** status, age_gt, unused, exempt_names


### Recordset

**Resource Type:** `recordset`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** status, age_gt, unused, exempt_names


### Record

**Resource Type:** `record`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** status, age_gt, unused, exempt_names




## Policy Structure

All policies for Designate follow this structure:

```yaml
version: v1
defaults:
  workers: 50
  output: findings.json
policies:
  - designate:
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
  description: Find inactive designate resources
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
  description: Find unused designate resources
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
  description: Audit designate resources
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


### Zone Examples


#### Find Inactive Zone Resources

```yaml
- name: find-inactive-zone
  description: Find inactive zone resources
  resource: zone
  check:
    status: inactive
  action: log
```

#### Find Old Zone Resources

```yaml
- name: find-old-zone
  description: Find zone resources older than 30 days
  resource: zone
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused Zone Resources

```yaml
- name: cleanup-unused-zone
  description: Delete unused zone resources
  resource: zone
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```


### Recordset Examples


#### Find Inactive Recordset Resources

```yaml
- name: find-inactive-recordset
  description: Find inactive recordset resources
  resource: recordset
  check:
    status: inactive
  action: log
```

#### Find Old Recordset Resources

```yaml
- name: find-old-recordset
  description: Find recordset resources older than 30 days
  resource: recordset
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused Recordset Resources

```yaml
- name: cleanup-unused-recordset
  description: Delete unused recordset resources
  resource: recordset
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```


### Record Examples


#### Find Inactive Record Resources

```yaml
- name: find-inactive-record
  description: Find inactive record resources
  resource: record
  check:
    status: inactive
  action: log
```

#### Find Old Record Resources

```yaml
- name: find-old-record
  description: Find record resources older than 30 days
  resource: record
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused Record Resources

```yaml
- name: cleanup-unused-record
  description: Delete unused record resources
  resource: record
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```



## Complete Policy Example

Here's a complete policy file example for Designate:

```yaml
version: v1
defaults:
  workers: 50
  output: findings.json
policies:
  - designate:
    - name: audit-zone
      description: Audit zone resources
      resource: zone
      severity: medium
      category: hygiene
      check:
        status: active
      action: log
    - name: cleanup-old-zone
      description: Find zone resources older than 90 days
      resource: zone
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
    - name: audit-recordset
      description: Audit recordset resources
      resource: recordset
      severity: medium
      category: hygiene
      check:
        status: active
      action: log
    - name: cleanup-old-recordset
      description: Find recordset resources older than 90 days
      resource: recordset
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
    - name: audit-record
      description: Audit record resources
      resource: record
      severity: medium
      category: hygiene
      check:
        status: active
      action: log
    - name: cleanup-old-record
      description: Find record resources older than 90 days
      resource: record
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
```

## OpenStack Documentation References

For more information about Designate resources and their properties:

- **OpenStack Designate API Documentation:** https://docs.openstack.org/api-ref/designate/
- **Designate Service Guide:** https://docs.openstack.org/designate/latest/
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
- Ensure service name matches exactly: `designate`
- Verify resource type is supported: `{zone DNS zones [status age_gt unused exempt_names] [] [log delete tag] {false false false}}`, `{recordset DNS recordsets [status age_gt unused exempt_names] [] [log delete tag] {false false false}}`, `{record DNS records [status age_gt unused exempt_names] [] [log delete tag] {false false false}}`
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
