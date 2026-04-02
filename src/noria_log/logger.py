from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .cloudwatch import create_cloudwatch_destination
from .file import create_file_destination
from .redaction import create_redact_matcher, parse_comma_separated_list, sanitize_log_value
from .targets import LoggerRuntimeContext, create_logger_runtime_context

LEVEL_VALUES = {
    "trace": 10,
    "debug": 20,
    "info": 30,
    "warn": 40,
    "error": 50,
    "fatal": 60,
    "silent": 70,
}


@dataclass(slots=True)
class ManagedLogger:
    logger: ServiceLogger
    flush: Any
    close: Any


class StdDestination:
    def __init__(self, stream: Any) -> None:
        self._stream = stream

    def emit_line(self, line: str, *, timestamp_ms: int | None = None) -> None:
        self._stream.write(f"{line}\n")

    def flush(self) -> None:
        self._stream.flush()

    def close(self) -> None:
        self._stream.flush()


class ServiceLogger:
    def __init__(
        self,
        *,
        level: str,
        schema: dict[str, str],
        base_fields: dict[str, Any],
        destinations: list[Any],
        redact_matcher: Any,
    ) -> None:
        self._level = level
        self._schema = schema
        self._base_fields = base_fields
        self._destinations = destinations
        self._redact_matcher = redact_matcher

    def log(self, level: str, message: str, **fields: Any) -> None:
        if LEVEL_VALUES[level] < LEVEL_VALUES[self._level]:
            return
        record, timestamp = self._build_record(level, message, fields)
        rendered = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
        for destination in self._destinations:
            destination.emit_line(rendered, timestamp_ms=timestamp)

    def trace(self, message: str, **fields: Any) -> None:
        self.log("trace", message, **fields)

    def debug(self, message: str, **fields: Any) -> None:
        self.log("debug", message, **fields)

    def info(self, message: str, **fields: Any) -> None:
        self.log("info", message, **fields)

    def warn(self, message: str, **fields: Any) -> None:
        self.log("warn", message, **fields)

    def warning(self, message: str, **fields: Any) -> None:
        self.warn(message, **fields)

    def error(self, message: str, **fields: Any) -> None:
        self.log("error", message, **fields)

    def fatal(self, message: str, **fields: Any) -> None:
        self.log("fatal", message, **fields)

    def exception(self, message: str, error: BaseException, **fields: Any) -> None:
        self.log("error", message, err=error, **fields)

    def _build_record(
        self, level: str, message: str, fields: dict[str, Any]
    ) -> tuple[dict[str, Any], int]:
        schema = self._schema
        timestamp = int(datetime.now(UTC).timestamp() * 1000)
        sanitized_fields = sanitize_log_value(dict(fields), self._redact_matcher)
        if "error" in sanitized_fields and schema["error_key"] not in sanitized_fields:
            sanitized_fields[schema["error_key"]] = sanitized_fields.pop("error")
        elif "err" in sanitized_fields and schema["error_key"] != "err":
            sanitized_fields[schema["error_key"]] = sanitized_fields.pop("err")
        record: dict[str, Any] = {
            schema["level_key"]: level,
            schema["level_value_key"]: LEVEL_VALUES[level],
            **self._time_fields(timestamp),
            **self._base_fields,
            **sanitized_fields,
            schema["message_key"]: message,
        }
        return record, timestamp

    def _time_fields(self, timestamp: int) -> dict[str, Any]:
        schema = self._schema
        fields: dict[str, Any] = {}
        if schema["time_mode"] in {"epoch", "both"}:
            fields[schema["time_key"]] = timestamp
        if schema["time_mode"] in {"iso", "both"}:
            fields[schema["timestamp_key"]] = (
                datetime.fromtimestamp(timestamp / 1000, tz=UTC)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )
        return fields


def create_service_logger(
    *,
    service_name: str,
    environment: str | None = None,
    level: str = "info",
    destinations: list[str] | None = None,
    schema: dict[str, str] | None = None,
    identity: dict[str, Any] | None = None,
    redact: dict[str, Any] | None = None,
    file: dict[str, Any] | None = None,
    redact_keys: list[str] | None = None,
    base: dict[str, Any] | None = None,
    cloudwatch: dict[str, Any] | None = None,
) -> ManagedLogger:
    destination_names = destinations or ["stdout"]
    resolved_schema = _resolve_schema_config(schema)
    redact_config = _resolve_redaction_config(redact, redact_keys)
    redact_matcher = create_redact_matcher(redact_config)
    runtime_context = create_logger_runtime_context(
        service_name=service_name,
        environment=environment,
        hostname=(identity or {}).get("hostname"),
        instance_id=(identity or {}).get("instanceId"),
        pid=(identity or {}).get("pid"),
    )
    managed_destinations = [
        _create_managed_destination(
            name, file=file, cloudwatch=cloudwatch, runtime_context=runtime_context
        )
        for name in destination_names
    ]
    logger = ServiceLogger(
        level=level,
        schema=resolved_schema,
        base_fields=_create_base_fields(
            service_name=service_name,
            environment=environment,
            base=base,
            schema=resolved_schema,
        ),
        destinations=managed_destinations,
        redact_matcher=redact_matcher,
    )
    return ManagedLogger(
        logger=logger,
        flush=lambda: [destination.flush() for destination in managed_destinations],
        close=lambda: [destination.close() for destination in managed_destinations],
    )


def parse_logger_destinations(raw_value: str | None = None) -> list[str]:
    entries = parse_comma_separated_list(raw_value) or ["stdout"]
    destinations = [entry.lower() for entry in entries]
    for destination in destinations:
        if destination not in {"stdout", "stderr", "file", "cloudwatch"}:
            raise ValueError(f"Unsupported logger destination '{destination}'.")
    return list(dict.fromkeys(destinations))


def _create_managed_destination(
    destination: str,
    *,
    file: dict[str, Any] | None,
    cloudwatch: dict[str, Any] | None,
    runtime_context: LoggerRuntimeContext,
) -> Any:
    import sys

    if destination == "stdout":
        return StdDestination(sys.stdout)
    if destination == "stderr":
        return StdDestination(sys.stderr)
    if destination == "file":
        if file is None:
            raise ValueError("file logging requires file configuration.")
        return create_file_destination(file, runtime_context)
    if destination == "cloudwatch":
        if cloudwatch is None:
            raise ValueError("cloudwatch logging requires cloudwatch configuration.")
        return create_cloudwatch_destination(cloudwatch, runtime_context)
    raise ValueError(f"Unsupported logger destination '{destination}'.")


def _resolve_schema_config(schema: dict[str, str] | None) -> dict[str, str]:
    resolved = {
        "message_key": (schema or {}).get("messageKey", "msg"),
        "level_key": (schema or {}).get("levelKey", "level"),
        "level_value_key": (schema or {}).get("levelValueKey", "levelValue"),
        "time_key": (schema or {}).get("timeKey", "time"),
        "timestamp_key": (schema or {}).get("timestampKey", "timestamp"),
        "service_key": (schema or {}).get("serviceKey", "service"),
        "environment_key": (schema or {}).get("environmentKey", "environment"),
        "error_key": (schema or {}).get("errorKey", "err"),
        "time_mode": (schema or {}).get("timeMode", "both"),
    }
    if resolved["time_mode"] == "both" and resolved["time_key"] == resolved["timestamp_key"]:
        raise ValueError(
            "schema.timeKey and schema.timestampKey must differ "
            "when both timestamp fields are enabled."
        )
    return resolved


def _resolve_redaction_config(
    redact: dict[str, Any] | None,
    redact_keys: list[str] | None,
) -> dict[str, Any]:
    if redact is not None:
        return {
            "keys": redact.get("keys", redact_keys or []),
            "mode": redact.get("mode", "merge"),
        }
    return {"keys": redact_keys or [], "mode": "merge"}


def _create_base_fields(
    *,
    service_name: str,
    environment: str | None,
    base: dict[str, Any] | None,
    schema: dict[str, str],
) -> dict[str, Any]:
    result = {schema["service_key"]: service_name}
    if environment:
        result[schema["environment_key"]] = environment
    if base:
        result.update(base)
    return result
