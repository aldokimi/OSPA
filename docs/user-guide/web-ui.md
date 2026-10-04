# Web UI

OSPA includes a browser UI (`cmd/server`) built with Go templates and HTMX. Use it to connect clouds via **profiles**, view cluster inventory, edit policies visually, and start dry-run audits.

!!! important "No automatic cloud connection"
    The UI never connects to OpenStack until you explicitly **Connect** a profile.
    Local `clouds.yaml` / `OS_CLOUD` are **not** used automatically. Using a local
    entry requires an explicit permission checkbox.

!!! warning "No UI authentication in v1"
    The HTTP UI has no login. Bind it to localhost or put it behind your own reverse
    proxy / SSO if you expose it on a network. OpenStack credentials for remote
    profiles are stored on the server host (see below).

## Start the server

```bash
go run ./cmd/server --listen :8080 --default-policy examples/policies.yaml
```

Or with a built binary:

```bash
go build -o ospa-ui ./cmd/server
./ospa-ui --listen :8080
```

Open [http://localhost:8080](http://localhost:8080).

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:8080` | HTTP listen address |
| `--default-policy` | `examples/policies.yaml` | Default policy path shown in the UI |

## Cloud profiles

Open **Profiles** in the nav. Profiles are how the UI authenticates to OpenStack.

### Remote profiles

Enter Keystone credentials (auth URL, username/password, project, domains, optional region). Credentials are saved under:

```text
~/.config/ospa/profiles.json   # mode 0600
```

You can connect immediately after save, or Connect later from the saved list.

### Local profiles (`clouds.yaml`)

If `clouds.yaml` entries exist on the host, they appear under **Use local clouds.yaml**.

1. Choose a cloud name
2. Check **I allow OSPA to use this local clouds.yaml entry**
3. Save (and optionally connect)

Connecting a saved local profile again also requires the permission checkbox. Nothing is authenticated until you confirm.

### Connect / disconnect

- **Connect** authenticates and sets the active session for Dashboard, Runs, and Policy dry-runs
- **Disconnect** clears the live session (inventory cache is dropped)
- Restarting the UI does **not** restore a live session — connect again when needed

Dashboard, Runs, and Policy Studio show a banner until a profile is connected. Start-run and inventory actions stay disabled until then.

## Pages

| Page | Purpose |
|------|---------|
| **Dashboard** | Inventory scan of the connected cloud vs policy coverage and recent findings |
| **Runs** | Start a dry-run (or apply) audit with a policy path; watch status and findings |
| **Policies** | Policy Studio — visual rule cards, type-driven create forms, YAML edit/validate/save |
| **Profiles** | Add/connect/disconnect remote or local cloud profiles |
| **Catalog** | Services and resource types registered in this build |

### Dashboard

With a connected profile, refresh to scan inventory (cached briefly; use **Force rescan** to bypass). Coverage shows managed / unmanaged / absent / unreachable types relative to the selected policy path.

### Runs

Uses the **connected** profile only (no cloud dropdown). Default is dry-run; enable **Apply remediations** only when you intend to change resources.

### Policy Studio

Build and edit rules as cards, filter by service/resource type, sync to/from YAML, validate, and save. **Start dry-run** from the YAML panel also requires a connected profile.

## CLI vs UI credentials

| Path | Credentials |
|------|-------------|
| `cmd/agent` (CLI) | `clouds.yaml` + `--cloud` / `OS_CLOUD` |
| `cmd/server` (UI) | Explicit **Profiles** connect only; optional local `clouds.yaml` with consent |

The CLI behavior is unchanged. See [Configuration](../getting-started/configuration.md) and [Running the Agent](running.md).

## Troubleshooting

### “No cloud connected”

Open **Profiles**, add or select a profile, and click **Connect** (with local consent if applicable).

### Local clouds not listed

Ensure `clouds.yaml` is discoverable (`OS_CLIENT_CONFIG_FILE` or standard OpenStack paths). Missing files are fine — use a remote profile instead.

### Auth failures on Connect

- Remote: check auth URL, username/password, project, and domain names
- Local: verify the named cloud in `clouds.yaml` and that Keystone is reachable from the UI host
