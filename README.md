# AgentSecrets

> **Zero-Knowledge Credential Infrastructure for AI Agents (and Humans and Teams)**: A unified enforcement pipeline—**store, inject, govern, audit**—that decouples credentials from the application runtime entirely, ensuring agents execute tasks using credentials by reference without ever holding or seeing the raw values.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev/)
[![Stars](https://img.shields.io/github/stars/The-17/agentsecrets?style=flat)](https://github.com/The-17/agentsecrets/stargazers)
[![ClawHub](https://img.shields.io/badge/ClawHub-agentsecrets-blue)](https://clawhub.ai/SteppaCodes/agentsecrets)

**[Website](https://agentsecrets.theseventeen.co)** | **[Docs](https://agentsecrets.theseventeen.co/docs)** | **[Engineering Blog](https://engineering.theseventeen.co/series/building-agentsecrets)**

---

Credentials are the backbone of the modern world. Every database, API, infrastructure, and system we interact with is protected by one thing: access. Yet as software becomes more autonomous, the layer that controls access has remained largely unchanged. We've spent years building more powerful applications, more capable AI systems, and more connected infrastructure — but we rarely ask: *what governs the keys that unlock them?*

AI agents make this problem impossible to ignore. An agent's capability is bounded by the credentials it holds, and without proper control, those credentials become the weakest link. We built AgentSecrets as the credential infrastructure for this new world — not just storing secrets, but governing how they're accessed, used, and enforced at runtime.

AgentSecrets is zero-knowledge credential infrastructure. It decouples credentials from the application runtime entirely, ensuring that agents execute tasks using credentials by reference without ever holding the raw values in memory.

To achieve this, AgentSecrets acts as an extensible infrastructure host. Specific security guarantees are enforced by **subsystems** that plug into AgentSecrets:

| Subsystem / Layer | System | What It Solves | Claim |
|:------------------|:-------|:---------------|:------------|
| **Credential Infrastructure** | AgentSecrets (Host) | Agent credential theft & lifecycle management | Extensible zero-knowledge infrastructure: credentials are resolved and injected at runtime without agents holding secret values |
| **Capability Bounding Subsystem** | [Keychain-Auth](https://github.com/The-17/keychain-auth) | Static, long-lived, over-privileged local credentials | OS-level keychain integration with process identity validation and dynamic session bounding |

AgentSecrets compiles these subsystems into a cohesive, provably secure framework. At no step does the agent hold, see, or have access to the actual credential value. The zero-knowledge guarantee is architectural, not policy-based.


---

## Contents

- [Why the Architecture Matters](#why-the-architecture-matters)
- [What AgentSecrets Is](#what-agentsecrets-is)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [The Agent Workflow](#the-agent-workflow)
- [Environments](#environments)
- [Team Workspaces](#team-workspaces)
- [Agent Identity](#agent-identity)
- [Secret-Level Policies & Approvals](#secret-level-policies--approvals)
- [6 Auth Injection Styles](#6-auth-injection-styles)
- [Zero-Trust Proxy Security](#zero-trust-proxy-security)
- [Encryption Model](#encryption-model)
- [AI Tool Integrations](#ai-tool-integrations)
- [Build on AgentSecrets](#build-on-agentsecrets)
- [Full Command Reference](#full-command-reference)
- [Roadmap](#roadmap)
- [Security](#security)
- [Contributing](#contributing)

---

> **Package rename notice**
> The `agentsecrets` PyPI package is now the [AgentSecrets SDK](https://github.com/The-17/agentsecrets-sdk): for developers building tools and agents on AgentSecrets infrastructure. The CLI wrapper is now `agentsecrets-cli`. The `agentsecrets` command itself is unchanged.

---

## The Critical Difference

There are two fundamentally different approaches to secrets management for AI agents.

**Runtime retrieval (the common pattern)**

The agent fetches or leases a credential at runtime. The value enters agent memory.

```bash
export TOKEN=$(secrets lease github_token)
# The agent now holds sk_live_51H... in memory
```

Once the value enters agent context, it can be extracted via prompt injection, exposed in logs or traces, and accessed by tools, plugins, or any dependency running in the same process.

**Zero-knowledge injection (AgentSecrets)**

The agent references a key name. The value is resolved outside the agent and injected at the transport layer.

```bash
agentsecrets call --bearer GITHUB_TOKEN
# The agent referenced a name. It never received a value.
```

If a system gives an AI agent access to a credential value, it must accept that the value can be leaked. AgentSecrets removes that assumption entirely.

---

## Why the Architecture Matters

Most approaches to AI agent credential security follow the same pattern: store secrets securely, then retrieve and inject them at runtime.

```
Secure store → agent retrieves sk_live_51H... → value enters agent memory
                                               → prompt injection can reach it
                                               → malicious plugin can read it
                                               → CVE exposes it
                                               → LLM trace captures it
```

Whether the store is a .env file, HashiCorp Vault, AWS Secrets Manager, or a leasing system, if the agent retrieves the value, the value is in agent context. That is the moment of exposure.

AgentSecrets eliminates that moment entirely.

```
OS keychain → proxy resolves in memory → value injected at transport layer
                                       → agent receives API response only
                                       → value never entered agent context
                                       → nothing to steal, log, or extract
```

The agent never retrieves the value. It cannot be prompted to reveal it. It cannot be logged. It cannot be stolen through a plugin or CVE. It was structurally absent from every place an attack would look.

---

## Extensible Security Architecture

AgentSecrets hosts modular subsystems to provide layered defense-in-depth:

**Zero-Knowledge Credential Core:** Six auth injection styles, client-side encryption (X25519, AES-256-GCM, Argon2id), response body redaction, SSRF protection, and environment variable injection (`agentsecrets env -- <cmd>`). The server stores client-encrypted ciphertext it structurally cannot decrypt.

**Capability Bounding (Keychain-Auth):** Protects OS keychain access via process verification (Anti-Impersonation). It verifies the cryptographic hash of calling processes (like the CLI or proxy) and restricts credentials to authorized execution namespaces with session capability boundaries.

**Environments & Teams:** Switches contexts (`development`, `staging`, `production`) instantly. Syncs secrets client-side via NaCl SealedBox key exchange across team workspaces. No plaintext keys touch the wire or disk.

**Identity & Audit Logs:** Maps executions to cryptographically issued Agent Tokens (when configured). The forensic log is SHA-256 chain-linked — tampering, deletion, or reordering is mathematically detectable. No value field exists in the schema.

**Developer SDK & MCP:** Build MCP servers, plugins, and agents where credential values are resolved below the runtime loop. The SDK has no `get()` method to prevent accidental or malicious retrieval.

**MCP integration:** first-class MCP server for Claude Desktop and Cursor. No credential values in any config file.

**Environment variable injection:** `agentsecrets env -- <command>` wraps any process and injects secrets from the OS keychain at spawn time. Stdout/stderr streams are scanned — any credential echo is redacted before hitting the console. Nothing written to disk.

---

## Installation

```bash
# Homebrew (macOS / Linux)
brew install The-17/tap/agentsecrets

# npm
npm install -g @the-17/agentsecrets

# pip
pip install agentsecrets-cli

# Go (recommend using a pinned version for supply chain security)
go install github.com/The-17/agentsecrets/cmd/agentsecrets@v3.0.0
```

---

## Quick Start

```bash
agentsecrets init

agentsecrets project create my-agent

# Set a single secret
agentsecrets secrets set STRIPE_KEY=sk_live_51H...

# Set multiple secrets at once
agentsecrets secrets set STRIPE_KEY=sk_live_51H... OPENAI_KEY=sk-proj-...

agentsecrets workspace allowlist add api.stripe.com api.openai.com

agentsecrets mcp install        # Claude Desktop + Cursor
agentsecrets proxy start        # any agent via HTTP proxy
```

---

## The Agent Workflow

This is what AgentSecrets looks like when an AI agent operates the full credentials lifecycle autonomously.

```bash
agentsecrets status

AgentSecrets Status

  ──────────────────────────────
  Logged in as:        alice@theseventeen.co
  Session:             Active (expires 5 hours from now)
  Refresh Token:       Available
  Selected Workspace:  Acme Engineering (shared)
  Environment:         production (from project.json)
  Current Project:     payments-service (in Acme Engineering)
  Proxy:               Running (port 8765)
  Secrets:             12 synced (0 unsynced)
  Activity:            Last Push: 2 minutes ago | Last Pull: 5 minutes ago

agentsecrets secrets diff
# Comparing secrets & allowlist...
#
# SECRETS:
#
#   In Cloud but missing in Local:
#     STRIPE_KEY
#
# Run agentsecrets secrets pull to sync from cloud.

agentsecrets secrets pull
# Pulling 1 secret and allowlist...
# Successfully synced cloud secrets and allowlist domains.

agentsecrets call \
  --url https://api.stripe.com/v1/balance \
  --bearer STRIPE_KEY
# {"object":"balance","available":[{"amount":420000,"currency":"usd"}]}

agentsecrets proxy logs --last 5
# 14:23:01  GET  api.stripe.com/v1/balance  STRIPE_KEY  200  245ms
```

The agent managed the complete workflow. No credential value appeared at any step. The audit log has no value field because there was no value to log.

---

## Environments

Every project has three built-in environments. One command switches the active context. The proxy, push, pull, and diff commands all respect the active environment automatically.

```bash
agentsecrets environment switch production

agentsecrets environment list
#   development   12 secrets
#   staging        8 secrets
#   production    12 secrets   ← active

agentsecrets secrets diff --from development --to production
# In development but missing in production:
#   OPENAI_KEY
#   DATABASE_URL

agentsecrets environment merge staging production
# Prompts for production values for each staging key
```

---

## Team Workspaces

```bash
agentsecrets workspace create "The Seventeen Engineering"
agentsecrets workspace invite alice@theseventeen.co bob@theseventeen.co

agentsecrets project create payments-service
agentsecrets project create auth-service
```

New developer onboards:
```bash
agentsecrets login
agentsecrets workspace switch "The Seventeen Engineering"
agentsecrets project use payments-service
agentsecrets secrets pull
# Ready. No credential sharing. No .env files sent over Slack.
```

---

## Agent Identity

```bash
# Declared identity
client = AgentSecrets(agent_id="billing-processor")

# Issued identity, cryptographically verified on every call
agentsecrets agent token issue "billing-processor"
# → agt_ws01hxyz_4kR9mNpQ...
client = AgentSecrets(agent_token="agt_ws01hxyz_...")

# Restrict what secrets an agent can use
agentsecrets agent policy set billing-processor \
  --allow STRIPE_KEY \
  --deny OPENAI_KEY

# Audit by agent
agentsecrets logs list --agent billing-processor
agentsecrets logs list --identity anonymous   # find coverage gaps
```

Agent capabilities are enforced at the proxy boundary — before credential resolution. An agent with `--deny OPENAI_KEY` cannot use that credential regardless of what it requests.

---

## Secret-Level Policies & Approvals

Define per-secret rules that govern which domains and HTTP methods can use each credential.

```bash
# Allow GET, require approval for POST
agentsecrets secrets policy set STRIPE_KEY \
  --rule "api.stripe.com:GET=allow" \
  --rule "api.stripe.com:POST=request_permission"
```

When a `request_permission` policy is triggered, the proxy holds the HTTP connection open and prompts for developer approval — in real time, without re-running the command:

**Proxy terminal** — immediate interactive prompt:
```
Approval Required
──────────────────────────────
Secret:   STRIPE_KEY  |  Agent: billing-processor
Request:  POST → api.stripe.com

Allow? [y/N/always]:
```

**Caller terminal** — hint appears after 2 seconds:
```
⏳ Waiting for approval...
   → Check the proxy terminal, or run:
     agentsecrets proxy approve STRIPE_KEY POST api.stripe.com
```

Type `y` in either terminal. The blocked request proceeds immediately — no re-run required. Approvals are session-scoped (reset on proxy restart).

---

## 6 Auth Injection Styles

```bash
# Bearer token
agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY

# Custom header
agentsecrets call --url https://api.sendgrid.com/v3/mail/send \
  --header X-Api-Key=SENDGRID_KEY

# Query parameter
agentsecrets call \
  --url "https://maps.googleapis.com/maps/api/geocode/json?address=Lagos" \
  --query key=GOOGLE_MAPS_KEY

# Basic auth
agentsecrets call --url https://jira.example.com/rest/api/2/issue \
  --basic JIRA_CREDS

# JSON body injection
agentsecrets call --url https://api.example.com/auth \
  --body-field client_secret=SECRET

# Form field injection
agentsecrets call --url https://oauth.example.com/token \
  --form-field api_key=KEY
```

---

## Zero-Trust Proxy Security

Every proxied request passes through a fail-fast security pipeline before credential injection:

**Secret presence check:** is the referenced key name in the local index? Blocks typos and non-existent keys before any network activity.

**HTTPS enforcement:** plaintext `http://` targets are blocked — no credential is ever sent over unencrypted transport.

**Agent token validation:** token checked against the cloud, capabilities extracted. Workspace, project, and environment scope restrictions enforced.

**Agent capability check:** per-token allow/deny lists evaluated before any credential is resolved. A denied key cannot be accessed regardless of other policy.

**Domain allowlist:** deny-by-default. Every target domain must be explicitly authorized. Unauthorized domains are blocked before credential resolution.

**Secret-level policy:** per-secret domain + method rules evaluated. Actions: `allow`, `deny`, or `request_permission` (holds the request open for interactive developer approval).

**SSRF protection:** private IP ranges, localhost, and non-HTTPS targets are blocked at the proxy level.

**Response body redaction:** if an external API echoes the injected credential in its response body, the proxy replaces it with `[REDACTED_BY_AGENTSECRETS]` before the response reaches the agent. Catches exact matches, API-truncated variants (e.g. `RESTRICT*DDUH`), URL-encoded forms, JSON-escaped forms, and long-prefix leaks.

**Session token:** generated at proxy startup, required on every request. Blocks rogue processes on the same machine from using the proxy.

```bash
agentsecrets workspace allowlist add api.stripe.com api.openai.com
agentsecrets workspace allowlist list
agentsecrets workspace allowlist log   # view blocked attempts
```

---

## Encryption Model

| Layer | Implementation |
|---|---|
| Key exchange | X25519 (NaCl SealedBox) |
| Secret encryption | AES-256-GCM |
| Key derivation | Argon2id |
| Key storage | OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service) |
| Transport | HTTPS / TLS |
| Server | Stores ciphertext only, structurally cannot decrypt |
| Audit chain | SHA-256 hash chaining (tamper-evident) |

---

## AI Tool Integrations

### Claude Desktop + Cursor

```bash
agentsecrets mcp install
```

```json
{
  "mcpServers": {
    "agentsecrets": {
      "command": "/usr/local/bin/agentsecrets",
      "args": ["mcp", "serve"]
    }
  }
}
```

### OpenClaw

```bash
openclaw skill install agentsecrets
```

Native exec provider for OpenClaw's SecretRef system. Credentials resolve at execution time through the AgentSecrets binary. Nothing in any OpenClaw config file.

### Environment Variable Injection

```bash
agentsecrets env -- stripe mcp
agentsecrets env -- node server.js
agentsecrets env -- python manage.py runserver
agentsecrets env -- npm run dev
```

Values injected into child process memory at spawn time. Nothing written to disk. Gone when the process exits.

### HTTP Proxy

```bash
agentsecrets proxy start

curl http://localhost:8765/proxy \
  -H "X-AS-Target-URL: https://api.stripe.com/v1/balance" \
  -H "X-AS-Inject-Bearer: STRIPE_KEY"
```

Works with LangChain, CrewAI, AutoGen, and any framework that makes HTTP requests.

---

## Build on AgentSecrets

```python
pip install agentsecrets
```

```python
from agentsecrets import AgentSecrets

client = AgentSecrets()
response = client.call(
    url="https://api.stripe.com/v1/balance",
    bearer="STRIPE_KEY"
)
```

The SDK has no `get()` method. There is no way to retrieve a credential value into calling code. The only operations available are the ones that keep the value out of agent context. The secure path is the only path.

**Built on the SDK:**
- [Zero-Knowledge MCP Template](https://github.com/The-17/zero-knowledge-mcp): scaffold for MCP servers with zero credential storage
- [AgentSecrets for LangChain](https://github.com/The-17/agentsecrets-langchain): zero-knowledge API calls in any LangChain agent *(coming soon)*
- [AgentSecrets JS SDK](https://github.com/The-17/agentsecrets-js-sdk) *(coming soon)*

---

## Full Command Reference

### Account
```bash
agentsecrets init                    # Set up account or initialise a new project
agentsecrets login                   # Login to existing account
agentsecrets logout                  # Clear session
agentsecrets status                  # Workspace, project, environment, last sync
```

### Workspaces
```bash
agentsecrets workspace create "Name"
agentsecrets workspace list
agentsecrets workspace switch "Name"
agentsecrets workspace invite user1@email.com user2@email.com
agentsecrets workspace promote user@email.com
agentsecrets workspace demote user@email.com
agentsecrets workspace allowlist add <domain>
agentsecrets workspace allowlist list
agentsecrets workspace allowlist log
```

### Projects
```bash
agentsecrets project create NAME
agentsecrets project list
agentsecrets project use NAME
agentsecrets project update NAME
agentsecrets project delete NAME
agentsecrets project invite user@email.com
```

### Environments
```bash
agentsecrets environment switch <n>
agentsecrets environment list
agentsecrets environment copy <from> <to>
agentsecrets environment merge <from> <to>
agentsecrets environment clean
```

### Secrets
```bash
agentsecrets secrets set KEY=value
agentsecrets secrets list
agentsecrets secrets push
agentsecrets secrets pull
agentsecrets secrets delete KEY
agentsecrets secrets diff
agentsecrets secrets diff --from X --to Y
agentsecrets secrets policy set KEY --rule "domain:METHOD=action"
agentsecrets secrets policy get KEY
agentsecrets secrets policy delete KEY
```

### Proxy and Calls
```bash
agentsecrets call --url URL --bearer KEY
agentsecrets proxy start [--port 8765]
agentsecrets proxy status
agentsecrets proxy stop
agentsecrets proxy approve <SECRET_KEY> <METHOD> <DOMAIN>
agentsecrets proxy rotate-session
agentsecrets proxy logs [--last N] [--watch] [--env ENV]
agentsecrets proxy sync
agentsecrets mcp serve
agentsecrets mcp install
agentsecrets exec
agentsecrets env -- <command>
```

### Audit
```bash
agentsecrets logs [--tail] [--agent NAME] [--identity anonymous]
agentsecrets logs show <id>           # Detailed forensic audit trace
agentsecrets logs summary [--since 7d]
agentsecrets logs export --format csv
agentsecrets logs verify              # Verify log cryptographic chain integrity
agentsecrets logs replay <id>         # Step-by-step visual log playback
agentsecrets logs watch               # Live stream audit entries
```

### Agent Identity
```bash
agentsecrets agent list
agentsecrets agent register <name>
agentsecrets agent delete <n>
agentsecrets agent policy set <name> --allow KEY --deny KEY
agentsecrets agent policy get <name>
agentsecrets agent token issue <n> [--env ENV] [--expires-in 30d]
agentsecrets agent token list <n>
agentsecrets agent token revoke <id> --agent="<n>"
```

---

## Roadmap

- [x] Core CLI
- [x] Zero-knowledge cloud sync
- [x] Credential proxy with 6 auth styles
- [x] Workspaces, projects, team invites
- [x] MCP server (Claude Desktop, Cursor) — 19 tools
- [x] HTTP proxy server
- [x] OpenClaw skill + exec provider
- [x] Forensic governance audit log (SHA-256 chain, verify, replay)
- [x] Agent identity + token management
- [x] Agent capabilities (allow/deny per token)
- [x] Secret-level policies (domain + method rules, request_permission)
- [x] Interactive approval flow (immediate prompt, no re-run required)
- [x] Environment support (development / staging / production)
- [x] Domain allowlist + enhanced response body redaction
- [x] SSRF & DNS rebinding protection
- [x] `agentsecrets env` for environment variable injection + stdout/stderr redaction
- [x] Zero-disk configuration (all keys in OS keychain)
- [x] Transient proxy (always-on security)
- [x] Python SDK
- [x] Zero-Knowledge MCP Template
- [x] Multi-platform binaries (macOS, Linux, Windows)
- [x] npm, pip, Homebrew distribution
- [ ] AgentSecrets for LangChain
- [ ] AgentSecrets for CrewAI
- [ ] JavaScript / Node.js SDK
- [ ] Secret rotation
- [ ] Web dashboard
- [ ] Cloud resolver (serverless + production deployments)
- [ ] AgentSecrets Connect (multi-tenant credential delegation)

---

## Security

### Trust Model & OS Keychain
AgentSecrets delegates authentication and cryptography to the user's local OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service). Be mindful of which workspace and environment you configure for your agents, as they will have access to any credentials provisioned in that specific scope. However, unwanted actions and API calls are heavily mitigated by the domain allowlist, which bounds where agents can send those credentials.

### Audit Logging Privacy
Every proxy call is recorded in a persistent audit log (locally at `~/.agentsecrets/audit.db` and globally in the cloud). The log records endpoints, timestamps, and key names (e.g., `STRIPE_KEY`), but never the actual values. **Do not put sensitive data in the key names themselves.**

### Supply Chain Security
Your security depends on the integrity of the installed `agentsecrets` package. We strongly recommend installing from official sources (like Homebrew) which verify package hashes, or using pinned versions for `go install` (e.g., `@v3.0.0` instead of `@latest`) to mitigate upstream supply chain poisoning.

Vulnerabilities: do NOT open public issues.
Email: engineering@theseventeen.co, response within 24 hours.

---

## Contributing

```bash
git clone https://github.com/The-17/agentsecrets
cd agentsecrets
go mod download
make build
make test
```

Found a bug? [Open an issue](https://github.com/The-17/agentsecrets/issues)
Have an idea? [Start a discussion](https://github.com/The-17/agentsecrets/discussions)
Want to contribute? [CONTRIBUTING.md](docs/CONTRIBUTING.md)

---

## Links

- **Website**: [agentsecrets.theseventeen.co](https://agentsecrets.theseventeen.co)
- **Docs**: [agentsecrets.theseventeen.co/docs](https://agentsecrets.theseventeen.co/docs)
- **Engineering Blog**: [engineering.theseventeen.co/series/building-agentsecrets](https://engineering.theseventeen.co/series/building-agentsecrets)
- **SDK**: [github.com/The-17/agentsecrets-sdk](https://github.com/The-17/agentsecrets-sdk)
- **ClawHub**: [clawhub.ai/SteppaCodes/agentsecrets](https://clawhub.ai/SteppaCodes/agentsecrets)

 ---
## License
MIT. See [LICENSE](LICENSE)

Built by [The Seventeen](https://theseventeen.co)

---

*You cannot steal what was never there.*
