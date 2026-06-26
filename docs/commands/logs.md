# agentsecrets logs

> Stream, export, and summarize global backend audit histories.

## Usage

```bash
agentsecrets logs <command> [flags]
```

## Description

The `logs` commands access your permanent, tamper-resistant backend audit ledger. This functionality empowers teams to verify exactly which AI agent triggered what API, under what identity, and whether they successfully executed their autonomous flows without unauthorized data spillage.

## Available Commands

### `list`
Retrieves a paginated or streamable list of proxy events matching specific criteria over a workspace or project.

```bash
agentsecrets logs list
agentsecrets logs list --identity <agent-id> --days 30
agentsecrets logs list --tail    # securely stream live global audits in real time
```

### `export`
Exports global logs off-platform for reporting and compliance tracking. It safely formats historical data (exports strictly omit plaintext credential payload fields).

```bash
agentsecrets logs export --format json > audit.json
agentsecrets logs export --format csv --days 90
```

### `summary`
Generates high-level statistical usage metrics aggregating API traffic, failure rates, and success boundaries.

```bash
agentsecrets logs summary
agentsecrets logs summary --days 7
```

### `detail`
Displays deep, granular metadata regarding a specific request UUID block.

```bash
agentsecrets logs detail <log-id>
```
