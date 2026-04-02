# `noria-log`

Structured JSON logging for Python services, with support for `stdout`, `stderr`, rotating file targets, and direct CloudWatch delivery.

This package is intentionally small and explicit. It does not wrap the standard `logging` module. Instead, it gives you a service logger that writes JSON records directly to one or more destinations, with schema remapping, secret redaction, target resolution, and CloudWatch batching built in.

## Install

```bash
pip install noria-log
```

Python requirement: `>=3.11`

## Main Exports

```python
from noria_log import (
    ManagedLogger,
    LoggerRuntimeContext,
    LoggerTargetContext,
    create_cloudwatch_destination,
    create_file_destination,
    create_logger_runtime_context,
    create_logger_target_context,
    create_redact_matcher,
    create_service_logger,
    format_date_stamp,
    parse_logger_destinations,
    parse_logger_redact_keys,
    resolve_target,
    sanitize_log_value,
)
```

## Quick Start

```python
from noria_log import create_service_logger

managed = create_service_logger(
    service_name="payments",
    environment="production",
)

logger = managed.logger

logger.info("service started", provider="stripe")
logger.warn("slow upstream", duration_ms=812)
logger.exception("payment failed", RuntimeError("gateway timeout"), invoice_id="inv_123")

managed.flush()
managed.close()
```

## What `create_service_logger()` Returns

`create_service_logger()` returns a `ManagedLogger` dataclass with:

- `logger`: the `ServiceLogger` instance
- `flush()`: flushes every configured destination
- `close()`: flushes and closes managed destinations

Call `close()` before process exit when you use file or CloudWatch destinations.

## Logger Methods

The returned `logger` exposes:

- `trace(message, **fields)`
- `debug(message, **fields)`
- `info(message, **fields)`
- `warn(message, **fields)`
- `warning(message, **fields)`
- `error(message, **fields)`
- `fatal(message, **fields)`
- `exception(message, error, **fields)`
- `log(level, message, **fields)`

Supported levels are:

- `trace`
- `debug`
- `info`
- `warn`
- `error`
- `fatal`
- `silent`

Records below the configured threshold are skipped.

## Default Output Shape

By default, each log record contains:

```json
{
  "level": "info",
  "levelValue": 30,
  "time": 1711580000000,
  "timestamp": "2024-03-27T12:13:20.000Z",
  "service": "payments",
  "environment": "production",
  "msg": "service started"
}
```

Additional keyword arguments passed to the logger are merged into the record.

Exception values are normalized into objects with:

- `name`
- `message`
- `stack`

## Basic Configuration

```python
from noria_log import create_service_logger

managed = create_service_logger(
    service_name="api",
    environment="staging",
    level="debug",
    destinations=["stdout", "file"],
    base={"team": "platform", "region": "eu-west-1"},
    redact_keys=["session_id"],
    file={
        "target": {
            "prefix": "/var/log/noria/api",
            "rotation": "daily",
            "suffix": ".jsonl",
        }
    },
)
```

### `create_service_logger()` Options

- `service_name`: required service identifier added to every record
- `environment`: optional environment name added to every record
- `level`: minimum level, default `info`
- `destinations`: list of destination names, default `["stdout"]`
- `schema`: field remapping configuration
- `identity`: runtime identity overrides for hostname, instance id, and pid
- `redact`: advanced redaction configuration
- `redact_keys`: extra exact-match redact keys
- `base`: base fields merged into every record
- `file`: file destination configuration, required when `file` is enabled
- `cloudwatch`: CloudWatch destination configuration, required when `cloudwatch` is enabled

## Destinations

Supported destination names are:

- `stdout`
- `stderr`
- `file`
- `cloudwatch`

Use `parse_logger_destinations()` if you want to accept a comma-separated environment variable:

```python
from noria_log import parse_logger_destinations

destinations = parse_logger_destinations("stdout,file,cloudwatch")
```

The parser:

- defaults to `["stdout"]` when the input is empty
- lowercases entries
- removes duplicates
- raises `ValueError` for unsupported names

## Schema Remapping

Use the `schema` option to rename output fields and choose which time fields are emitted.

```python
managed = create_service_logger(
    service_name="billing",
    schema={
        "messageKey": "message",
        "levelKey": "severity",
        "levelValueKey": "severityValue",
        "timeKey": "ts",
        "timestampKey": "tsIso",
        "serviceKey": "app",
        "environmentKey": "stage",
        "errorKey": "error",
        "timeMode": "iso",
    },
)
```

Supported schema keys:

- `messageKey`: default `msg`
- `levelKey`: default `level`
- `levelValueKey`: default `levelValue`
- `timeKey`: default `time`
- `timestampKey`: default `timestamp`
- `serviceKey`: default `service`
- `environmentKey`: default `environment`
- `errorKey`: default `err`
- `timeMode`: one of `epoch`, `iso`, `both`

Rules:

- `timeMode="epoch"` emits only the integer millisecond timestamp
- `timeMode="iso"` emits only the ISO timestamp
- `timeMode="both"` emits both
- when `timeMode="both"`, `timeKey` and `timestampKey` must be different

## Redaction

Redaction happens before records are encoded to JSON.

By default, the built-in matcher treats keys containing common secret-like names as sensitive, including:

- `token`
- `secret`
- `key`
- `password`
- `authorization`
- `credential`
- `api_key`

### Simple Redaction

```python
managed = create_service_logger(
    service_name="auth",
    redact_keys=["session_id", "otp"],
)
```

### Advanced Redaction

```python
managed = create_service_logger(
    service_name="auth",
    redact={
        "keys": ["session_id"],
        "mode": "replace",
    },
)
```

`redact.mode` controls how custom keys behave:

- `merge`: exact keys are added to the built-in secret matcher
- `replace`: only the explicitly listed keys are redacted

`redact_keys` and `redact["keys"]` can be combined. If `redact` is provided, its `mode` wins.

You can also use the helpers directly:

```python
from noria_log import create_redact_matcher, sanitize_log_value

matcher = create_redact_matcher({"keys": ["session_id"], "mode": "merge"})
safe = sanitize_log_value({"token": "secret", "session_id": "abc"}, matcher)
```

## Runtime Identity

By default, runtime context uses the current hostname and process id. Override it with `identity` when you need deterministic names in tests or custom deployment metadata:

```python
managed = create_service_logger(
    service_name="worker",
    identity={
        "hostname": "queue-1",
        "instanceId": "i-abc123",
        "pid": 4242,
    },
)
```

Available identity keys:

- `hostname`
- `instanceId`
- `pid`

## Base Fields

Use `base` to inject fields into every record:

```python
managed = create_service_logger(
    service_name="payments",
    base={
        "team": "platform",
        "component": "webhook-consumer",
    },
)
```

Base fields are merged after the standard service and environment fields.

## File Destination

Enable the file destination by including `"file"` in `destinations` and supplying `file=...`.

```python
managed = create_service_logger(
    service_name="api",
    destinations=["file"],
    file={
        "target": {
            "prefix": "/var/log/noria/api",
            "rotation": "daily",
            "suffix": ".jsonl",
        },
        "mkdir": True,
    },
)
```

### File Config

- `target`: required target config
- `mkdir`: optional, default `True`; creates parent directories automatically

### File Target Resolution

`file["target"]` supports three styles:

1. Fixed path

```python
file={"target": {"value": "/var/log/noria/api.jsonl"}}
```

2. Declarative path building

```python
file={
    "target": {
        "prefix": "/var/log/noria/api",
        "rotation": "monthly",
        "includeServiceName": True,
        "includeEnvironment": True,
        "includeHostname": True,
        "includeInstanceId": True,
        "includePid": True,
        "suffix": ".jsonl",
        "separator": "/",
        "timezone": "America/New_York",
    }
}
```

3. Custom resolver

```python
file={
    "target": {
        "resolve": lambda context: (
            f"/var/log/{context.environment}/{context.service_name}-{context.pid}.jsonl"
        )
    }
}
```

Supported target keys:

- `value`: fixed path
- `prefix`: base path or prefix
- `rotation`: `none`, `daily`, `monthly`, `annual`
- `timezone`: IANA timezone used for rotation boundaries
- `includeServiceName`
- `includeEnvironment`
- `includeHostname`
- `includeInstanceId`
- `includePid`
- `identifier`
- `separator`: join string, default `-`
- `suffix`
- `resolve`: callable that receives `LoggerTargetContext`

Important behavior:

- file targets are resolved per event timestamp, not only once at startup
- that allows date-aware rollovers from the actual event time
- if the emitted JSON contains `time` or `timestamp`, the file destination uses it to choose the target

## CloudWatch Destination

Enable the CloudWatch destination by including `"cloudwatch"` in `destinations` and supplying `cloudwatch=...`.

```python
managed = create_service_logger(
    service_name="api",
    destinations=["stdout", "cloudwatch"],
    cloudwatch={
        "region": "eu-west-1",
        "logGroupName": "/noria/api",
        "stream": {
            "prefix": "api",
            "rotation": "daily",
            "includeHostname": False,
            "includePid": False,
        },
        "retentionInDays": 30,
    },
)
```

### CloudWatch Config

- `region`: required unless you inject `client`
- `logGroupName`: required
- `credentials`: optional mapping with `access_key_id`, `secret_access_key`, `session_token`
- `client`: optional boto logs client override
- `stream`: optional target config for stream names
- `createLogGroup`: default `True`
- `createLogStream`: default `True`
- `retentionInDays`: optional CloudWatch retention policy
- `flushIntervalMs`: default `2000`
- `maxBatchCount`: default `1000`
- `maxBatchBytes`: default `900000`
- `maxBufferedEvents`: default `20000`
- `retryBaseDelayMs`: default `1000`

### Stream Naming

CloudWatch stream naming uses the same target resolution engine as file targets.

If you do not provide `stream`, the fallback stream name is:

```text
{hostname}-{pid}
```

When you provide a rotating stream prefix, rotation happens from each event timestamp, not wall-clock flush time.

### Retention Values

Supported `retentionInDays` values are:

`1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653`

### CloudWatch Operational Behavior

- log events are buffered in memory and flushed in batches
- batches are grouped by stream name
- oversized buffers are trimmed from the oldest events
- transient flush failures are retried with backoff
- CloudWatch setup can create the log group and stream automatically

## Target Helper Functions

These helpers are available when you want to build your own file or CloudWatch wrappers:

```python
from noria_log import (
    create_logger_runtime_context,
    create_logger_target_context,
    format_date_stamp,
    resolve_target,
)
```

Example:

```python
runtime = create_logger_runtime_context(
    service_name="payments",
    environment="prod",
)

target_context = create_logger_target_context(runtime, 1711578600000)

path = resolve_target(
    {
        "prefix": "logs",
        "rotation": "daily",
        "includeServiceName": True,
        "includeEnvironment": True,
        "suffix": ".jsonl",
        "separator": "/",
    },
    target_context,
)
```

## Direct Destination Construction

If you do not want the full managed logger, you can create destinations directly:

```python
from noria_log import create_cloudwatch_destination, create_file_destination

runtime = create_logger_runtime_context(service_name="api", environment="prod")

file_destination = create_file_destination(
    {"target": {"value": "/tmp/api.jsonl"}},
    runtime,
)

cloudwatch_destination = create_cloudwatch_destination(
    {
        "region": "eu-west-1",
        "logGroupName": "/noria/api",
        "createLogGroup": False,
        "createLogStream": False,
    },
    runtime,
)
```

Each destination exposes:

- `emit_line(line, timestamp_ms=None)`
- `flush()`
- `close()`

## Usage Patterns

### Stdout Only

```python
managed = create_service_logger(service_name="api")
managed.logger.info("ready")
```

### Stdout and File

```python
managed = create_service_logger(
    service_name="api",
    destinations=["stdout", "file"],
    file={"target": {"prefix": "/tmp/api", "rotation": "daily", "suffix": ".jsonl"}},
)
```

### File Only with Custom Schema

```python
managed = create_service_logger(
    service_name="jobs",
    destinations=["file"],
    schema={"messageKey": "message", "errorKey": "error", "timeMode": "iso"},
    file={"target": {"value": "/tmp/jobs.log"}},
)
```

### CloudWatch Only

```python
managed = create_service_logger(
    service_name="worker",
    destinations=["cloudwatch"],
    cloudwatch={
        "region": "eu-west-1",
        "logGroupName": "/noria/worker",
    },
)
```

## Notes and Caveats

- `close()` is the safe way to finish file and CloudWatch logging
- `StdDestination.close()` only flushes; it does not close `stdout` or `stderr`
- file and CloudWatch targets can rotate based on the timestamp inside each emitted JSON record
- `warn()` and `warning()` are equivalent
- passing `error=` or `err=` fields is normalized to the configured error key
- JSON is emitted with compact separators and `ensure_ascii=False`

## Development

Run tests:

```bash
uv sync --extra dev
uv run pytest
```

Run lint:

```bash
uv run ruff check .
```
