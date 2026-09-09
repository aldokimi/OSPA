# Policy Guide: Swift (swift)

This guide explains how to write policies for Swift resources in OSPA.

## Service Overview

**Service Name:** `swift`
**Display Name:** Swift
**OpenStack Service Type:** object-store

## Supported Resources


### Account

**Resource Type:** `account`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** status, age_gt, unused, exempt_names


### Container

**Resource Type:** `container`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** status, age_gt, unused, exempt_names


### Object

**Resource Type:** `object`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** status, age_gt, unused, exempt_names




## Policy Structure

All policies for Swift follow this structure:

```yaml
version: v1
defaults:
  workers: 50
  output: findings.json
policies:
  - swift:
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
  description: Find inactive swift resources
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
  description: Find unused swift resources
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
  description: Audit swift resources
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


### Account Examples


#### Find Inactive Account Resources

```yaml
- name: find-inactive-account
  description: Find inactive account resources
  resource: account
  check:
    status: inactive
  action: log
```

#### Find Old Account Resources

```yaml
- name: find-old-account
  description: Find account resources older than 30 days
  resource: account
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused Account Resources

```yaml
- name: cleanup-unused-account
  description: Delete unused account resources
  resource: account
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```


### Container Examples


#### Find Inactive Container Resources

```yaml
- name: find-inactive-container
  description: Find inactive container resources
  resource: container
  check:
    status: inactive
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


### Object Examples


#### Find Inactive Object Resources

```yaml
- name: find-inactive-object
  description: Find inactive object resources
  resource: object
  check:
    status: inactive
  action: log
```

#### Find Old Object Resources

```yaml
- name: find-old-object
  description: Find object resources older than 30 days
  resource: object
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused Object Resources

```yaml
- name: cleanup-unused-object
  description: Delete unused object resources
  resource: object
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```



## Complete Policy Example

Here's a complete policy file example for Swift:

```yaml
version: v1
defaults:
  workers: 50
  output: findings.json
policies:
  - swift:
    - name: audit-account
      description: Audit account resources
      resource: account
      severity: medium
      category: hygiene
      check:
        status: active
      action: log
    - name: cleanup-old-account
      description: Find account resources older than 90 days
      resource: account
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
        status: active
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
    - name: audit-object
      description: Audit object resources
      resource: object
      severity: medium
      category: hygiene
      check:
        status: active
      action: log
    - name: cleanup-old-object
      description: Find object resources older than 90 days
      resource: object
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
```

## OpenStack Documentation References

For more information about Swift resources and their properties:

- **OpenStack Swift API Documentation:** https://docs.openstack.org/api-ref/swift/
- **Swift Service Guide:** https://docs.openstack.org/swift/latest/
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
- Ensure service name matches exactly: `swift`
- Verify resource type is supported: `{account Accounts [status age_gt unused exempt_names] [] [log delete tag] {false false false}}`, `{container Containers [status age_gt unused exempt_names] [] [log delete tag] {false false false}}`, `{object Objects [status age_gt unused exempt_names] [] [log delete tag] {false false false}}`
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
