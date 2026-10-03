# Policy Guide: Trove (trove)

**Service Name:** `trove`
**OpenStack Service Type:** database

## Supported Resources

### Instance (`instance`)
- Checks: `status`, `age_gt`, `exempt_names`
- Actions: `log`, `delete`

### Cluster (`cluster`)
- Checks: `status`, `age_gt`, `exempt_names`
- Actions: `log`, `delete`

### Backup (`backup`)
- Checks: `age_gt`, `exempt_names`
- Actions: `log`, `delete`

### Datastore (`datastore`)
- Checks: `age_gt`, `exempt_names`
- Actions: `log`, `delete`
