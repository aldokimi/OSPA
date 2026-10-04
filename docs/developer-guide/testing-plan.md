# OSPA Full Testing Plan

Goal: prove OSPA works correctly across CLI, Web UI, policies, and every live OpenStack service — before release and on every meaningful change.

## 1. Quality gates (definition of “working”)

| Gate | Pass criteria |
|------|----------------|
| **G1 Build** | `go build ./...` succeeds for `cmd/agent`, `cmd/server`, `cmd/scaffold` |
| **G2 Unit** | `go test ./pkg/... -count=1` green; race clean on critical packages |
| **G3 Lint/Vet** | `go vet ./...` + golangci-lint green |
| **G4 E2E (core)** | Against DevStack/cloud: neutron + glance + keystone + nova packages exercise create→audit→cleanup (not only skip) |
| **G5 E2E (catalog)** | `go test -tags=e2e ./e2e/...` overall green; unavailable services **skip**, never fail |
| **G6 CLI smoke** | Dry-run agent against sample policy produces findings JSON/CSV without panic |
| **G7 UI smoke** | Server starts; Profiles connect/disconnect; dashboard refresh; Policy Studio validate; dry-run from UI |
| **G8 Docs** | mkdocs build succeeds; CLI/UI commands in docs match flags |

Release rule: **G1–G3 + G6 + G7 required**. **G4–G5 required** when OpenStack credentials are available (nightly / pre-release).

---

## 2. Test pyramid

```text
        ┌──────────────────┐
        │  Manual / UI QA  │  profiles, studio, dashboard
        ├──────────────────┤
        │  E2E (OpenStack) │  create → audit → remediate dry-run
        ├──────────────────┤
        │  Integration     │  auth, runner, policy load, inventory
        ├──────────────────┤
        │  Unit            │  auditors, validators, composites, store
        └──────────────────┘
```

| Layer | Location | Cloud? | Owner cadence |
|-------|----------|--------|---------------|
| Unit | `pkg/**/*_test.go` | No | Every PR (CI) |
| Integration | `pkg/auth` integration tag, `pkg/runner`, inventory | Optional | PR when touched; nightly with cloud |
| E2E | `e2e/<service>/` | Yes (`OS_CLOUD`) | Nightly / pre-release |
| UI | Manual + future httptest | No OpenStack until Connect | Every UI PR + release |
| Docs | mkdocs | No | Docs PRs |

---

## 3. Layer plans

### 3.1 Unit (`pkg/`)

**Always run**

```bash
go test ./pkg/... -count=1
go test -race ./pkg/audit/... ./pkg/policy/... ./pkg/orchestrator/... ./pkg/runner/... -count=1
go test -coverprofile=pkg.cover.out ./pkg/...
go tool cover -func=pkg.cover.out | tail -20
```

**Must cover**

| Area | Focus |
|------|--------|
| Auditors | Each `Check()` path for declared `ImplementedChecks()`; type assertion failures |
| Composites | Registered patterns (Neutron/Octavia/etc.) with fixture graphs |
| Policy | `Load` / `LoadBytes`, validators per service, export/marshal round-trip |
| Common helpers | status (case-insensitive), age_gt, unused, exempt_names |
| Runner / orchestrator | cancel context, dry-run vs apply, allow-actions |
| Cloudprofile store | upsert/delete/active, password redaction in `Public()` |
| Dashboard stats | inventory + policy coverage math |
| Runstore | concurrent append/status |

**Coverage targets (aspirational)**

- Critical packages (`audit/*`, `policy`, `orchestrator`, `runner`): ≥ 70% statements
- New code in a PR: tests required for new check branches

### 3.2 Integration

```bash
# Auth against real cloud (skips if OS_CLOUD unset when not tagged appropriately)
OS_CLOUD=devstack go test -tags=integration ./pkg/auth/... -count=1 -v

# Inventory + runner smoke (scripted)
OS_CLOUD=devstack go test ./pkg/inventory/... ./pkg/runner/... -count=1
```

**Scenarios**

1. `NewSession` + service clients for every enabled catalog entry
2. `NewSessionFromCredentials` with remote-style fields (UI path)
3. Inventory scan returns reachable services without panic
4. Runner dry-run with tiny policy finishes and summarizes

### 3.3 E2E (`e2e/`)

```bash
export OS_CLOUD=devstack   # or OS_CLIENT_CONFIG_FILE=...
go test -tags=e2e ./e2e/... -count=1 -timeout 45m
```

**Maturity matrix (maintain this)**

| Service | E2E package | Live creator | Notes |
|---------|-------------|--------------|-------|
| neutron | yes | **yes** | Gold standard |
| glance | yes | **yes** | Image + member |
| keystone | yes | **yes** | User/project/group/role/domain/service |
| nova | yes | **yes** | Keypair/flavor/instance; hypervisor N/A |
| cinder | yes | stub | Skip until volumev3 available |
| barbican | yes | stub | Skip if not in catalog |
| designate | yes | stub | Skip if not in catalog |
| heat | yes | stub | Skip if not in catalog |
| swift | yes | stub | Skip if not in catalog |
| ironic | yes | stub | Skip if not in catalog |
| magnum | yes | stub | Skip if not in catalog |
| octavia | yes | stub | Package present; implement creators when LB enabled |
| manila | yes | stub | Same |
| trove | yes | stub | Same |
| senlin | yes | stub | Service still stub auditors |
| zaqar | yes | stub | Service still stub auditors |

**Per-resource E2E checklist** (already scaffolded; enforce when creators are live)

- [ ] Status / age / unused / exempt_names
- [ ] Discovery of created resource
- [ ] Classification fields on findings
- [ ] JSON + CSV output
- [ ] Delete/tag dry-run skip + allow-actions filter
- [ ] Cleanup / orphan sweeper

**Rule:** missing service → `t.Skip` via `skipOrFail`. Missing creator → `t.Skip` in `Create*`. Never `t.Fatal` for catalog absence.

### 3.4 CLI smoke

```bash
go build -o bin/ospa-agent ./cmd/agent
./bin/ospa-agent --cloud "$OS_CLOUD" --policy examples/policies.yaml --out /tmp/ospa-findings.json
test -s /tmp/ospa-findings.json
./bin/ospa-agent --cloud "$OS_CLOUD" --policy examples/policies.yaml --out /tmp/ospa-findings.csv --out-format csv
# Negative: bad cloud / bad policy must exit non-zero with clear error
```

### 3.5 Web UI smoke

```bash
go run ./cmd/server --listen :8080 --default-policy examples/policies.yaml
```

| Step | Expect |
|------|--------|
| Open `/` | Banner: no cloud connected; refresh disabled |
| Profiles → remote or local+consent → Connect | Banner connected; disconnect works |
| Local without checkbox | Rejected |
| Dashboard refresh | Inventory metrics or clear inventory error |
| Policies | Add rule card, sync YAML, validate OK |
| Runs | Start dry-run; findings stream; cancel optional |
| Restart server | Not auto-connected |

**Security checks (release)**

- Profiles file mode `0600` under `~/.config/ospa/profiles.json`
- No secrets in HTML responses (password redacted)
- UI still has no login — document bind to localhost / reverse proxy

### 3.6 Scaffold / regen

```bash
go test ./cmd/scaffold/... -count=1
go run ./cmd/scaffold --list
```

Ensure new services get auditor + discovery + validator + e2e stubs that compile under `-tags=e2e`.

---

## 4. CI / automation plan

### Today

| Workflow | What runs |
|----------|-----------|
| `ci.yml` | `go test ./pkg/...`, vet, golangci-lint |
| `docs.yml` | mkdocs (on docs changes) |
| `scaffold-tests.yml` | scaffold package tests |

### Recommended additions

1. **PR CI (keep fast)**  
   - Current unit + lint  
   - `go test -tags=e2e ./e2e/...` **without** `OS_CLOUD` → all skip, proves compile under e2e tag

2. **Nightly / workflow_dispatch “e2e-devstack”**  
   - Self-hosted or secret-bearing runner with DevStack  
   - `OS_CLOUD=devstack go test -tags=e2e ./e2e/... -timeout 45m`  
   - Upload junit/log artifact  
   - Fail if neutron/glance/keystone/nova have zero non-skip tests (detect stub regression)

3. **UI job (optional)**  
   - Start `cmd/server`, curl `/healthz`, `/profiles`, `/`

4. **Coverage comment**  
   - `pkg.cover.out` threshold warn on large drops

---

## 5. Pre-release checklist

Copy into the release PR:

- [ ] G1–G3 green on `main`
- [ ] E2E core (neutron, glance, keystone, nova) green on target cloud
- [ ] Full `e2e/...` green (skips OK for absent services)
- [ ] CLI dry-run + sample policy
- [ ] UI profile connect (remote **and** local consent path)
- [ ] Policy Studio create/validate/save
- [ ] Dashboard inventory matches cloud roughly
- [ ] No secrets in logs or UI HTML
- [ ] Docs: Web UI + CLI flags current
- [ ] Senlin/Zaqar still marked stub in README/catalog if auditors no-op

---

## 6. Gap backlog (make tests “perfect”)

Prioritized work to close remaining holes:

| Priority | Item | Why |
|----------|------|-----|
| P0 | CI compile check with `-tags=e2e` | Catch broken e2e on every PR |
| P0 | Assert non-skip count for core services in nightly | Prevent silent all-skip “green” |
| P1 | Implement cinder creators when volume API present | Core storage path |
| P1 | Octavia/Manila/Trove creators on enriched DevStack | Live services without e2e depth |
| P1 | UI httptest/Playwright suite for Profiles + Runs | Regressions in HTMX flows |
| P2 | Barbican/Designate/Heat/Swift/Ironic/Magnum creators | Catalog completeness |
| P2 | Remediation apply e2e in isolated project | Prove delete/tag safely |
| P2 | Composite-pattern e2e fixtures | High-signal security rules |
| P3 | Un-stub Senlin/Zaqar auditors + e2e | README honesty |
| P3 | Mutation/fuzz on policy YAML loader | Parser robustness |

---

## 7. Day-to-day commands

```bash
# PR default
make test
golangci-lint run   # if installed

# Before merging cloud-touching changes
OS_CLOUD=devstack go test -tags=e2e ./e2e/neutron/... ./e2e/glance/... ./e2e/keystone/... ./e2e/nova/... -count=1 -timeout 30m

# Full e2e
OS_CLOUD=devstack make test-e2e

# UI
make server
```

---

## 8. Ownership

| Area | When to update this plan |
|------|---------------------------|
| New service / resource | Add row to maturity matrix + creator TODO |
| New composite | Unit fixtures + optional e2e |
| UI feature | Add UI smoke step |
| CI change | Update §4 |

Related: [Testing guide](testing.md), [Web UI](../user-guide/web-ui.md), [Audit checks overview](../Audit_Checks_Overview.md).
