# `noria-log`

Structured JSON logging for Python services, with support for `stdout`, `stderr`, file targets, and direct CloudWatch delivery.

## Install

```bash
pip install noria-log
```

## Quick Start

```python
from noria_log import create_service_logger

managed = create_service_logger(
    service_name="payments",
    environment="production",
)

logger = managed.logger
flush_logger = managed.flush
close_logger = managed.close

logger.info("service started", provider="stripe")
```

## Features

- structured JSON output
- schema remapping for message, level, time, service, environment, and error fields
- secret redaction with merge or replace modes
- multi-destination logging
- file targets with timestamp-based rotation
- direct CloudWatch delivery with batching, retries, retention, and rotating streams

## Testing

```bash
uv sync --extra dev
uv run pytest
```
