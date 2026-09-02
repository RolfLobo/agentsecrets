# agentsecrets status

> Inspect session state, active project context, server connection, and keychain-auth daemon health.

## Usage

```bash
agentsecrets status
```

---

## Output Fields

* **CLI Version & Build**: Active release version.
* **Server Endpoint**: Target server URL and resolution source (Default vs. Self-Hosted).
* **Workspace & Project**: Active workspace role, project binding, and environment branch.
* **Keychain Backend**: `keychain-auth` daemon connection status and binary attestation state.

For complete status options and troubleshooting, visit:
👉 **[System Status Documentation](https://docs.agentsecrets.tech/cli/status)**