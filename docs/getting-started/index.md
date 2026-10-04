# Getting Started

Welcome to OSPA! This section will help you get up and running with the OpenStack Policy Agent.

## Overview

OSPA is a policy-driven audit and remediation agent for OpenStack clouds. In just a few steps, you can:

1. **Install** OSPA on your system
2. **Configure** credentials (`clouds.yaml` for the CLI, or **Profiles** in the Web UI)
3. **Create** your first policy
4. **Run** an audit against your cloud (CLI or browser)

## What You'll Need

Before you begin, make sure you have:

- **Go 1.21+** installed ([download](https://go.dev/dl/))
- **OpenStack access** with valid credentials
- For the CLI: a `clouds.yaml` file (or env-based OpenStack config)
- For the Web UI: either remote Keystone credentials or an opt-in local `clouds.yaml` entry (the UI does not auto-connect)

## Quick Navigation

<div class="grid cards" markdown>

-   **Installation**

    ---

    Clone the repository, install dependencies, and build OSPA.

    [→ Installation Guide](installation.md)

-  **Quick Start**

    ---

    Run your first audit in under 5 minutes.

    [→ Quick Start Tutorial](quickstart.md)

- **Configuration**

    ---

    Set up clouds.yaml and environment variables.

    [→ Configuration Guide](configuration.md)

- **Web UI**

    ---

    Connect profiles, browse inventory, and edit policies in the browser.

    [→ Web UI](../user-guide/web-ui.md)

</div>

## Next Steps

After completing the getting started guide, explore:

- [User Guide](../user-guide/index.md) - Learn to write policies and run audits
- [Web UI](../user-guide/web-ui.md) - Browser dashboard and Policy Studio
- [Developer Guide](../developer-guide/index.md) - Extend OSPA with new services
- [Reference](../reference/index.md) - CLI and policy schema reference

