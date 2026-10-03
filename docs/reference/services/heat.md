# Policy Guide: Heat (heat)

This guide explains how to write policies for Heat resources in OSPA.

## Service Overview

**Service Name:** `heat`
**Display Name:** Heat
**OpenStack Service Type:** orchestration

## Supported Resources


### Stack

**Resource Type:** `stack`

**Allowed Actions:** log, delete
**Allowed Checks:** status, age_gt, exempt_names

Stack status is the API's `stack_status` field (e.g. `CREATE_COMPLETE`,
`CREATE_FAILED`, `UPDATE_IN_PROGRESS`, `DELETE_COMPLETE`). There is no
"in use" signal for a stack, so `unused` is not offered.


### Resource

**Resource Type:** `resource`

**Allowed Actions:** log
**Allowed Checks:** status, age_gt, exempt_names

A resource is an element of a stack (identified as `stack-name/resource-name`).
Its status is `resource_status` (e.g. `CREATE_COMPLETE`, `CREATE_FAILED`,
`IN_PROGRESS`). Resources are only modified through their parent stack, so no
delete/tag remediation is offered.


### Template

**Resource Type:** `template`

**Allowed Actions:** log
**Allowed Checks:** exempt_names

A template is the read-only definition of its stack. The API exposes no
status or timestamps for it, so only `exempt_names` (matching the owning
stack's name) applies.


### Snapshot

**Resource Type:** `snapshot`

**Allowed Actions:** log
**Allowed Checks:** age_gt, exempt_names

A stack snapshot only exposes its capture time (`snapshot_time`); there is no
state field. The Heat API has no delete-snapshot endpoint, so only `log` is
offered.




## Policy Structure

All policies for Heat follow this structure:

```yaml
version: v1
defaults:
  workers: 50
  output: findings.json
policies:
  - heat:
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
  description: Find inactive heat resources
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
  description: Find unused heat resources
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
  description: Audit heat resources
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


### Stack Examples


#### Find Failed Stacks

```yaml
- name: find-failed-stacks
  description: Find stacks whose creation or update failed
  resource: stack
  check:
    status: CREATE_FAILED
  action: log
```

#### Find Old Stacks

```yaml
- name: find-old-stacks
  description: Find stacks older than 30 days
  resource: stack
  check:
    age_gt: 30d
  action: log
```

#### Delete Old Failed Stacks

```yaml
- name: delete-old-failed-stacks
  description: Delete failed stacks that are older than 90 days
  resource: stack
  check:
    status: CREATE_FAILED
    age_gt: 90d
  action: delete
```


### Resource Examples


#### Find Failed Stack Resources

```yaml
- name: find-failed-resources
  description: Find stack resources stuck in a failed state
  resource: resource
  check:
    status: CREATE_FAILED
  action: log
```

#### Find Old Stack Resources

```yaml
- name: find-old-resources
  description: Find stack resources older than 30 days
  resource: resource
  check:
    age_gt: 30d
  action: log
```

#### Find Failed Resources Except System Ones

```yaml
- name: find-failed-resources-except-system
  description: Find failed resources, exempting system ones
  resource: resource
  check:
    status: CREATE_FAILED
    exempt_names:
      - system_*
  action: log
```


### Template Examples

Templates have no status or timestamps of their own, so the only offered
check is `exempt_names`. Today this makes a template rule a placeholder for
future template-content checks (e.g. hardcoded credentials):

```yaml
- name: audit-stack-templates
  description: Audit stack templates, exempting system stacks
  resource: template
  check:
    exempt_names:
      - system-*
  action: log
```


### Snapshot Examples


#### Find Old Snapshots

```yaml
- name: find-old-snapshots
  description: Find stack snapshots older than 30 days
  resource: snapshot
  check:
    age_gt: 30d
  action: log
```

#### Find Old Snapshots Except System Stacks

```yaml
- name: find-old-snapshots-except-system
  description: Find old snapshots, exempting system stacks
  resource: snapshot
  check:
    age_gt: 30d
    exempt_names:
      - system-*
  action: log
```



## Complete Policy Example

Here's a complete policy file example for Heat:

```yaml
version: v1
defaults:
  workers: 50
  output: findings.json
policies:
  - heat:
    - name: find-failed-stacks
      description: Find stacks whose creation or update failed
      resource: stack
      severity: high
      category: hygiene
      check:
        status: CREATE_FAILED
      action: log
    - name: cleanup-old-stacks
      description: Find stacks older than 90 days
      resource: stack
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - system-*
      action: log
    - name: find-failed-resources
      description: Find stack resources stuck in a failed state
      resource: resource
      severity: medium
      category: hygiene
      check:
        status: CREATE_FAILED
      action: log
    - name: audit-stack-templates
      description: Audit stack templates, exempting system stacks
      resource: template
      severity: low
      category: hygiene
      check:
        exempt_names:
          - system-*
      action: log
    - name: find-old-snapshots
      description: Find stack snapshots older than 90 days
      resource: snapshot
      severity: low
      category: cost
      check:
        age_gt: 90d
      action: log
```

## OpenStack Documentation References

For more information about Heat resources and their properties:

- **OpenStack Heat API Documentation:** https://docs.openstack.org/api-ref/heat/
- **Heat Service Guide:** https://docs.openstack.org/heat/latest/
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
- Ensure service name matches exactly: `heat`
- Verify resource type is supported: `{stack Stacks [status age_gt exempt_names] [] [log delete] {false false false}}`, `{resource Stack resources [status age_gt exempt_names] [] [log] {false false false}}`, `{template Templates [exempt_names] [] [log] {false false false}}`, `{snapshot Stack snapshots [age_gt exempt_names] [] [log] {false false false}}`
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
