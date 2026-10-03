# Policy Guide: Zaqar (zaqar)

**Service Name:** `zaqar`
**OpenStack Service Type:** messaging

## Supported Resources

### Queue (`queue`)
- Checks: `status`, `age_gt`, `exempt_names`
- Actions: `log`, `delete`

### Message (`message`)
- Checks: `status`, `age_gt`, `exempt_names`
- Actions: `log`, `delete`

### Subscription (`subscription`)
- Checks: `status`, `age_gt`, `exempt_names`
- Actions: `log`, `delete`
