# OSPA Audit Checks Overview

> **Objective:** Analyze existing checks and identify gaps in the OSPA project for service-specific audit checks concerning OpenStack services.
>
> **Verified against:** policy guides in `docs/reference/services/*`, validators in `pkg/policy/validation/*`, and auditors in `pkg/audit/*` (as of 2026-10-04).

## Introduction

OSPA (OpenStack Policy Agent) is designed to conduct policy-driven audits and remediation within OpenStack environments. One of the crucial aspects of OSPA is ensuring that audit checks are not only effective but also tailored to the specifics of each OpenStack service. This document provides an analysis of the current status of various services supported by OSPA, discusses implemented checks, and identifies gaps where additional checks are necessary.

## Analysis per Service

> **Note:** “Declared” means what policy guides / validators advertise. “Implemented” means what `Auditor.ImplementedChecks()` + `Check()` actually evaluate.
>
> **Gap philosophy (important):** The absence of a check is a *gap* only if the underlying API/audit model can support it. When the API cannot provide required fields/state (or remediation is impossible), we call that out explicitly as an **API-audit model availability** gap.
>
> **Composite status:** `pkg/audit/composite.go` defines `CompositeAuditor` / `RegisterComposite`, but **no service currently registers a composite auditor**. Named catalog types below are candidate outcomes, not live check types.

### Implementation maturity legend

| Maturity | Meaning |
|----------|---------|
| **Live** | Discovery + auditor `Check()` evaluate conditions |
| **Declared-only** | Guide/validator lists a check that is not evaluated |
| **Stub** | Auditor returns empty compliant result (no real evaluation); often discovery is empty too |

### 1. Neutron (`neutron` / network) — Live

- **Supported Resources:** `network`, `security_group`, `security_group_rule`, `floating_ip`, `subnet`, `router`, `port`
- **Existing Checks:**
  - `network`: `shared_network` (high, security) + common `status/age_gt/unused/exempt_names`
  - `security_group`: common only
  - `security_group_rule` (**implemented**): `direction`, `ethertype`, `protocol`, `port`, `remote_ip_prefix` (critical; open-to-world when `0.0.0.0/0` or `::/0`), `port_range_wide` (span &gt;100 ports), `exempt_names`
  - Semantic observations on match: `public_sensitive_service_exposure` (world + SSH/RDP); `bidirectional_world_exposure` when policy omits `direction`
  - `port`: `no_security_group` (high, security)
  - `floating_ip`: `unassociated` (medium, cost)
  - plus common checks where declared
- **Gaps / enhancements (verified):**
  - **DONE (#102):** `port_range_wide` evaluation + named semantic exposure observations (atomic matching preserved).
  - **PARTIAL:** true peer-rule bidirectional escalation still needs a registered `CompositeAuditor` (see #103 / #107).
  - **REAL (cross-resource composite):** `shared_network_world_exposure` needs network ↔ security-group membership correlation; no `CompositeAuditor` does this yet.
  - Config-plane OSG items (TLS/auth/control-plane) remain **manual-only** — not audit-model gaps unless new inputs are added.

### 2. Nova (`nova` / compute) — Live

- **Supported Resources:** `instance`, `keypair`, `flavor`, `hypervisor`
- **Existing Checks (implemented):**
  - `instance`: `image_name`, `no_keypair`, plus common `status/age_gt/unused/exempt_names`
  - `keypair`: common `age_gt/unused/exempt_names` (`unused` is pending observation — needs instance enumeration)
  - `flavor`: `is_public` + `exempt_names`
  - `hypervisor`: `status`, `exempt_names`
- **Gaps / enhancements (verified):**
  - **PARTIAL:** “public flavor + instance on public/shared networks” is not a registered composite. Nova server objects already expose `Addresses` / flavor binding; joining to Neutron `shared`/`external` is the missing audit-model step (not “impossible”).
  - **DONE (#108):** `idle_no_keypair` observation when `unused` (SHUTOFF) and `no_keypair` both fire.
  - **REAL (config-plane):** TLS/auth between services remains manual OSG territory.

### 3. Cinder (`volumev3` / block storage) — Live (with snapshot mismatch)

- **Supported Resources:** `volume`, `snapshot`, `backup`, `qos`
- **Existing Checks:**
  - `volume` (**implemented**): `encrypted`, `attached`, `has_backup` + common
  - `snapshot`: guide claims `encrypted`; **validator rejects** `encrypted`; auditor `ImplementedChecks` omits it (comment: encryption inherited from source volume, not on snapshot resource) → treat as **declared-only / blocked**
  - `backup`: common `status/age_gt/exempt_names`
  - `qos`: `exempt_names` only
- **Gaps / enhancements (verified):**
  - **REAL:** backup retention window / compliance / backup↔volume matching beyond boolean `has_backup`.
  - **REAL:** QoS posture fields not modeled (only `exempt_names`).
  - **PARTIAL:** volume-level `encrypted=false` + `has_backup` can AND in one rule today. Richer “insufficient crypto controls” narrative still needs snapshot/backup encryption state (API-audit model gap for those resources).
  - **REAL (doc/code drift):** align guide + validator + auditor on snapshot `encrypted` (implement via source-volume join, or remove from guide).

### 4. Glance (`glance` / image) — Live

- **Supported Resources:** `image`, `member`
- **Existing Checks (implemented):**
  - `image`: `visibility` + common
  - `member`: common only (`unused` ≈ pending acceptance)
- **Gaps / enhancements (verified):**
  - **REAL (composite):** correlate `image.visibility` with member scope (`ImageID`/`MemberID` already on member) → candidate `public_image_cross_tenant_exposure`.
  - **PARTIAL:** “public image + sensitive tags” needs tag fields in `CheckConditions` (not modeled today).

### 5. Keystone (`keystone` / identity) — Live (admin role pending)

- **Supported Resources:** `user`, `role`, `project`, `domain`, `group`, `service`
- **Existing Checks:**
  - `user` (**implemented**): `password_expired`, `mfa_enabled` + common
  - `user` (**declared / pending**): `has_admin_role` — accepted but only emits “pending - requires role assignment enumeration”; does **not** set non-compliant
  - `role` / `group`: `age_gt/unused/exempt_names` only (**no `status`** — overview previously overstated)
  - `project` / `domain` / `service`: common as declared
- **Gaps / enhancements (verified):**
  - **REAL:** finish `has_admin_role` evaluation, then register `high_privilege_no_mfa` composite.
  - **DONE (#111):** `expired_password_no_mfa` observation when `password_expired` and `mfa_enabled` both fire.
  - **REAL:** MFA/posture for service users/groups at scale and admin-role inheritance need relationship model inputs.

### 6. Heat (`heat` / orchestration) — Live

- **Supported Resources:** `stack`, `resource`, `template`, `snapshot`
- **Existing Checks (implemented):** hygiene as declared; **`unused` correctly omitted** (no API in-use signal)
- **Gaps / enhancements (verified):**
  - **PARTIAL:** failed-stack root-cause composite (`failed_stack_root_cause`) is not built, but discovery already links resources via `HeatResourceInStack.StackName` and SDK exposes status reasons — closer than “no linkage.”
  - **REAL (API limitation):** orphaned-component cleanup cannot use `unused`; use status/age/dependency-aware alternatives instead.

### 7. Swift (`swift` / object-store) — Live (hygiene)

- **Supported Resources:** `account`, `container`, `object`
- **Existing Checks (implemented):** as declared (account `quota_set` log-only; container unused/exempt; object age/exempt)
- **Gaps / enhancements (verified):**
  - **REAL in OSPA model; SDK-capable:** container ACL headers (`Read`/`Write`) exist via container Get — not modeled because discovery/audit currently list-oriented.
  - **REAL until exposure fields exist:** composite like public container + old object.

### 8. Octavia (`octavia` / load-balancer) — Stub

- **Supported Resources:** `loadbalancer`, `listener`, `pool`, `member`, `healthmonitor`
- **Existing Checks:** declared hygiene only; **auditors are stubs** (`Check` returns empty compliant result)
- **Gaps / enhancements (verified):**
  - **REAL (blocked by stubs first):** wire live discovery + hygiene evaluation.
  - **REAL (OSPA model); SDK-capable:** listener `Protocol`, `ProtocolPort`, `TLSCiphers`, `DefaultTlsContainerRef` exist in gophercloud — TLS/protocol hardening is an OSPA modeling gap more than an OpenStack API gap.
  - Candidate composites once live: public LB + weak TLS min / insecure protocol + wide exposure.

### 9. Barbican (`barbican` / key-manager) — Live (hygiene)

- **Supported Resources:** `secret`, `container`, `order`
- **Existing Checks (implemented):** hygiene only (`status/age_gt/unused/exempt_names` as declared)
- **Gaps / enhancements (verified):**
  - **DONE (#100):** `secret_type` atomic check + `stale_secret_material` semantic observation when `age_gt` matches (optionally filtered by type). Freshness uses Updated/Created — API has no rotation field.
  - **PARTIAL (#119):** richer type→risk classification (algorithm/content-types) and usage/policy pairing still open.
  - **REAL (API-audit model):** no dedicated “last rotated” field.

### 10. Manila (`manila` / shared-file-systems) — Stub

- **Supported Resources:** `share`, `share_snapshot`, `share_network`, `share_server`
- **Existing Checks:** declared hygiene; **auditors are stubs**
- **Gaps / enhancements (verified):**
  - **REAL (blocked by stubs first):** wire live discovery + hygiene.
  - **REAL (missed implementable once live):** `is_public` / share visibility posture.
  - **PARTIAL / availability:** dedicated encryption-at-rest/in-transit fields are not clearly exposed on the share struct — confirm API before promising encryption composites.

### 11. Trove (`trove` / database) — Stub

- **Supported Resources:** `instance`, `cluster`, `backup`, `datastore`
- **Existing Checks:** declared hygiene; **auditors are stubs**
- **Gaps / enhancements (verified):**
  - **REAL (blocked by stubs first):** wire live discovery + hygiene.
  - **REAL:** backup retention/compliance beyond `age_gt`; TLS/transport posture only if audit model gains TLS/cert metadata.

### 12. Magnum (`magnum` / container-infra) — Live (truncated discovery)

- **Supported Resources:** `cluster`, `cluster_template`, `bay`, `baymodel`
- **Existing Checks (implemented):** age/status/hygiene as declared
- **Gaps / enhancements (verified):**
  - **REAL:** template/policy-level security configuration checks missing.
  - **REAL (audit-model truncation):** discovery currently keeps ID/Name/timestamps for templates — API has richer fields that are dropped before audit. Restore those fields before writing security checks.

### 13. Ironic (`ironic` / baremetal) — Live (guide drift)

- **Supported Resources:** `node`, `port`, `driver`, `chassis`
- **Existing Checks (implemented — differs from guide):**
  - `node`: `status`, `age_gt`, `unused`, `exempt_names`
  - `port`: `age_gt`, `exempt_names` only
  - `driver`: `exempt_names` only
  - `chassis`: `age_gt`, `exempt_names` only
- **Gaps / enhancements (verified):**
  - **REAL (doc drift):** policy guide claims status/unused for port/driver/chassis; validators/auditors do not — align docs.
  - **REAL:** provisioning-time insecure parameters (PXE/TLS/driver settings) not modeled; add if Ironic audit payloads expose them.

### 14. Designate (`designate` / dns) — Live

- **Supported Resources:** `zone`, `recordset`, `record`
- **Existing Checks (implemented):** hygiene as declared; recordset `unused` already uses `len(Records)==0`; **`record_type`** (#101) with `risky_dns_exposure` for A/AAAA
- **Gaps / enhancements (verified):**
  - **DONE (#101):** `record_type` atomic check using SDK `Type`/`Records`.
  - **PARTIAL:** zone-level exposure composites (public zone + risky records) still need cross-resource correlation (#103).

### 15. Senlin (`senlin` / clustering) — Stub

- **Supported Resources:** `cluster`, `profile`, `node`, `policy`
- **Existing Checks:** declared hygiene; **auditors are stubs** (empty `Check()`)
- **Gaps / enhancements (verified):**
  - **REAL (blocked by stubs first):** wire live discovery + hygiene before semantic work.
  - **REAL (API-audit model after live):** policy-composition security needs profile/policy **definition** fields, not just lifecycle metadata. Do not invent checks from age/status alone.

### 16. Zaqar (`zaqar` / messaging) — Stub

- **Supported Resources:** `queue`, `message`, `subscription`
- **Existing Checks:** declared hygiene; **auditors are stubs** (empty `Check()`)
- **Gaps / enhancements (verified):**
  - **REAL (blocked by stubs first):** wire live discovery + hygiene.
  - **REAL (cautious / availability):** payload/content risk only via sanitized metadata (e.g. content-type). Raw message body inspection is out of scope.


## Scaffolding Insights

The scaffolding tool provided within OSPA enables the generation of template checks for resources. However, it has some limitations:
- Manual intervention is often required to customize templates for more complex resource relationships.
- Composite/semantic checks are harder because they require consistent audit-model fields and cross-resource linking/identity (not just per-resource conditions).
- Several scaffolded services remain **stubs** (Octavia, Manila, Trove, Senlin, Zaqar) — declared checks are not yet functional.

## Key Gaps Across OSPA

### 1) Semantic/composite correlation gaps (biggest opportunity)
- Many policy guides enumerate *atomic* checks, but OSPA lacks registered composite auditors that turn co-occurring fields into **high-signal compliance outcomes**.
- Some “composites” are already expressible as a single-rule AND of atomics (Neutron world+port, Keystone password_expired+MFA, Cinder encrypted+has_backup, Nova unused+no_keypair). Prioritize naming/cataloging those vs inventing new fields.

### 2) Declared vs implemented drift
- Notable mismatches: Neutron `port_range_wide`; Cinder snapshot `encrypted`; Ironic port/driver/chassis check lists; Keystone `has_admin_role` pending.
- Fixing drift is often higher ROI than new composite types.

### 3) Stub services undercut the guide narrative
- Octavia / Manila / Trove / Senlin / Zaqar advertise hygiene checks that currently no-op. Treat “make live” as a prerequisite before semantic enhancements.

### 4) Composite checks constrained by audit-model availability
- Label honestly: Heat/Swift/Barbican usage fields, Magnum truncated templates, Manila encryption uncertainty, etc. Prefer “SDK has X but OSPA drops it” over “API cannot support X” when the SDK already exposes the field.

### 5) Lifecycle hygiene / unused signals
- Where APIs lack in-use signals (Heat; Magnum templates), reframe remediation around status/age/dependency checks rather than inventing `unused`.

## Gap catalog (composite pattern → candidate check type)

| Pattern | Candidate type | Status |
|---------|----------------|--------|
| Public exposure + critical ports | `public_sensitive_service_exposure` | PARTIAL — atomic AND works; named composite missing |
| Ingress + egress wide-open | `bidirectional_world_exposure` | REAL — needs peer-rule / composite eval |
| Shared scope + exposure rules | `shared_network_world_exposure` | REAL — needs membership correlation |
| Admin + no MFA | `high_privilege_no_mfa` | REAL — blocked on live `has_admin_role` |
| Password expired + no MFA | `expired_password_no_mfa` | DONE (#111) |
| Unencrypted volume + backup posture | `unencrypted_volume_backup_risk` | PARTIAL — volume AND-able; snapshot/backup crypto incomplete |
| Idle instance + no keypair | `idle_no_keypair` | DONE (#108) |
| Rotation freshness risk | `stale_secret_material` | PARTIAL — type/age SDK-capable; rotation/usage not |
| Public image + access scope | `public_image_cross_tenant_exposure` | REAL — member linkage exists; composite not registered |
| Failed stack + failed sub-resources | `failed_stack_root_cause` | PARTIAL — StackName linkage exists; composite not built |
| DNS risky record exposure | `risky_dns_exposure` | DONE (#101) for record_type A/AAAA; zone composites still open |

## Recommendations
1. Adopt the gap philosophy: missing checks are gaps only when the audit-model/SDK supports them; otherwise label **API-audit model availability**. Prefer “OSPA truncates SDK field X” when that is the real blocker.
2. Register a core composite-check pattern library (`RegisterComposite`) and document required inputs per pattern.
3. Prioritize by likelihood / ROI:
   1. Fix declared-vs-implemented drift (`port_range_wide`, snapshot `encrypted` story, Ironic guide, `has_admin_role`)
   2. Neutron world exposure semantic naming + `shared_network_world_exposure`
   3. Keystone `password_expired`+MFA (AND/catalog) and finish `has_admin_role` → `high_privilege_no_mfa`
   4. Un-stub Octavia/Manila/Trove (and model SDK TLS / `is_public` fields)
   5. Barbican `secret_type` + Designate record-type checks (SDK-ready)
4. Extend scaffolding so generated services are not left as permanent empty `Check()` stubs.
5. Keep a cadence vs OpenStack Security Guide updates; compare guide allowed checks ↔ `ImplementedChecks()` ↔ composite catalog.

## References
- [OpenStack Security Guide](https://docs.openstack.org/security-guide/)
- [OSPA Documentation](https://openstack-policy-agent.github.io/OSPA/)
- [OpenStack API Documentation (Nova)](https://docs.openstack.org/api-ref/nova/)
- Policy guides: `docs/reference/services/*`
- Auditors: `pkg/audit/*`
- Composite interface: `pkg/audit/composite.go`
