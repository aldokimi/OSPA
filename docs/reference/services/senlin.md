# Policy Guide: Senlin (senlin)

**Service Name:** `senlin`
**OpenStack Service Type:** clustering

## Supported Resources

### Cluster (`cluster`)
- Checks: `status`, `age_gt`, `exempt_names`
- Actions: `log`, `delete`

### Profile (`profile`)
- Checks: `age_gt`, `exempt_names`
- Actions: `log`, `delete`

### Node (`node`)
- Checks: `status`, `age_gt`, `exempt_names`
- Actions: `log`, `delete`

### Policy (`policy`)
- Checks: `age_gt`, `exempt_names`
- Actions: `log`, `delete`
