from __future__ import annotations

import json
import sys
import threading
from dataclasses import dataclass
from time import time_ns
from typing import Any

import boto3
from botocore.client import BaseClient
from botocore.exceptions import ClientError

from .targets import (
    LoggerRuntimeContext,
    create_logger_runtime_context,
    create_logger_target_context,
    resolve_target,
)

DEFAULT_FLUSH_INTERVAL_MS = 2_000
DEFAULT_MAX_BATCH_COUNT = 1_000
DEFAULT_MAX_BATCH_BYTES = 900_000
DEFAULT_MAX_BUFFERED_EVENTS = 20_000
DEFAULT_RETRY_BASE_DELAY_MS = 1_000
MAX_RETRY_DELAY_MS = 30_000
CLOUDWATCH_EVENT_OVERHEAD_BYTES = 26
SUPPORTED_RETENTION_DAYS = {
    1,
    3,
    5,
    7,
    14,
    30,
    60,
    90,
    120,
    150,
    180,
    365,
    400,
    545,
    731,
    1096,
    1827,
    2192,
    2557,
    2922,
    3288,
    3653,
}


@dataclass(slots=True)
class QueuedLogEvent:
    message: str
    timestamp: int
    bytes: int
    stream_name: str


class CloudWatchDestination:
    def __init__(self, config: dict[str, Any], runtime_context: LoggerRuntimeContext) -> None:
        self._config = config
        self._runtime_context = runtime_context
        self._client = config.get("client") or self._build_client(config)
        self._queue: list[QueuedLogEvent] = []
        self._queue_bytes = 0
        self._lock = threading.RLock()
        self._timer: threading.Timer | None = None
        self._closed = False
        self._log_group_initialized = False
        self._stream_initialized: set[str] = set()
        self._flush_in_flight = False
        self._retry_delay_ms = int(config.get("retryBaseDelayMs", DEFAULT_RETRY_BASE_DELAY_MS))

    def emit_line(self, line: str, *, timestamp_ms: int | None = None) -> None:
        try:
            stripped = line.strip()
        except Exception as error:
            raise ValueError(str(error)) from error
        if not stripped:
            return
        with self._lock:
            timestamp = timestamp_ms if timestamp_ms is not None else _extract_timestamp(stripped)
            stream_config = (
                self._config.get("stream") if isinstance(self._config.get("stream"), dict) else None
            )
            should_include_hostname = bool(
                stream_config
                and stream_config.get("rotation")
                and stream_config.get("rotation") != "none"
                and stream_config.get("prefix")
            )
            stream_name = resolve_target(
                stream_config,
                create_logger_target_context(self._runtime_context, timestamp),
                {
                    "value": f"{self._runtime_context.hostname}-{self._runtime_context.pid}",
                    "includeHostname": should_include_hostname,
                    "includePid": False,
                    "separator": "-",
                },
            )
            event = QueuedLogEvent(
                message=stripped,
                timestamp=timestamp,
                bytes=len(stripped.encode("utf-8")) + CLOUDWATCH_EVENT_OVERHEAD_BYTES,
                stream_name=stream_name,
            )
            self._queue.append(event)
            self._queue_bytes += event.bytes
            self._trim_queue_if_needed()
            max_batch_count = int(self._config.get("maxBatchCount", DEFAULT_MAX_BATCH_COUNT))
            max_batch_bytes = int(self._config.get("maxBatchBytes", DEFAULT_MAX_BATCH_BYTES))
            if len(self._queue) >= max_batch_count or self._queue_bytes >= max_batch_bytes:
                self.flush()
                return
            self._schedule_flush(
                int(self._config.get("flushIntervalMs", DEFAULT_FLUSH_INTERVAL_MS))
            )

    def flush(self) -> None:
        with self._lock:
            if self._flush_in_flight:
                return
            self._flush_in_flight = True
        try:
            self._flush_internal()
        finally:
            with self._lock:
                self._flush_in_flight = False

    def close(self) -> None:
        with self._lock:
            self._closed = True
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        self.flush()

    def _flush_internal(self) -> None:
        self._clear_timer()
        with self._lock:
            if not self._queue:
                return
        self._ensure_log_group()
        while True:
            with self._lock:
                if not self._queue:
                    break
                batch = self._take_batch()
            self._ensure_resources(batch[0].stream_name)
            try:
                self._client.put_log_events(
                    logGroupName=self._config["logGroupName"],
                    logStreamName=batch[0].stream_name,
                    logEvents=[
                        {"message": entry.message, "timestamp": entry.timestamp}
                        for entry in sorted(batch, key=lambda item: item.timestamp)
                    ],
                )
                self._retry_delay_ms = int(
                    self._config.get("retryBaseDelayMs", DEFAULT_RETRY_BASE_DELAY_MS)
                )
            except Exception as error:
                with self._lock:
                    self._queue = batch + self._queue
                    self._queue_bytes += sum(entry.bytes for entry in batch)
                    self._trim_queue_if_needed()
                self._write_internal_error("Failed to publish logs to CloudWatch.", error)
                self._schedule_flush(self._retry_delay_ms)
                self._retry_delay_ms = min(self._retry_delay_ms * 2, MAX_RETRY_DELAY_MS)
                return

    def _take_batch(self) -> list[QueuedLogEvent]:
        stream_name = self._queue[0].stream_name
        max_batch_count = int(self._config.get("maxBatchCount", DEFAULT_MAX_BATCH_COUNT))
        max_batch_bytes = int(self._config.get("maxBatchBytes", DEFAULT_MAX_BATCH_BYTES))
        batch: list[QueuedLogEvent] = []
        bytes_used = 0
        index = 0
        while index < len(self._queue) and len(batch) < max_batch_count:
            next_event = self._queue[index]
            if next_event.stream_name != stream_name:
                index += 1
                continue
            if batch and bytes_used + next_event.bytes > max_batch_bytes:
                break
            batch.append(next_event)
            bytes_used += next_event.bytes
            self._queue.pop(index)
            self._queue_bytes -= next_event.bytes
        return batch

    def _trim_queue_if_needed(self) -> None:
        max_buffered = int(self._config.get("maxBufferedEvents", DEFAULT_MAX_BUFFERED_EVENTS))
        while len(self._queue) > max_buffered:
            removed = self._queue.pop(0)
            self._queue_bytes -= removed.bytes

    def _schedule_flush(self, delay_ms: int) -> None:
        with self._lock:
            if self._closed or self._timer is not None:
                return
            self._timer = threading.Timer(delay_ms / 1000, self._timer_flush)
            self._timer.daemon = True
            self._timer.start()

    def _timer_flush(self) -> None:
        with self._lock:
            self._timer = None
        self.flush()

    def _clear_timer(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

    def _ensure_resources(self, stream_name: str) -> None:
        self._ensure_log_group()
        self._ensure_log_stream(stream_name)

    def _ensure_log_group(self) -> None:
        create_log_group = bool(self._config.get("createLogGroup", True))
        retention = self._config.get("retentionInDays")
        if self._log_group_initialized or (not create_log_group and retention is None):
            return
        if create_log_group:
            try:
                self._client.create_log_group(logGroupName=self._config["logGroupName"])
            except Exception as error:
                if not _is_aws_exists_error(error):
                    raise
        if retention is not None:
            if retention not in SUPPORTED_RETENTION_DAYS:
                raise ValueError(f"Unsupported CloudWatch retentionInDays '{retention}'.")
            self._client.put_retention_policy(
                logGroupName=self._config["logGroupName"],
                retentionInDays=retention,
            )
        self._log_group_initialized = True

    def _ensure_log_stream(self, stream_name: str) -> None:
        if (
            not bool(self._config.get("createLogStream", True))
            or stream_name in self._stream_initialized
        ):
            return
        try:
            self._client.create_log_stream(
                logGroupName=self._config["logGroupName"],
                logStreamName=stream_name,
            )
        except Exception as error:
            if not _is_aws_exists_error(error):
                raise
        self._stream_initialized.add(stream_name)

    def _build_client(self, config: dict[str, Any]) -> BaseClient:
        credentials = config.get("credentials") or {}
        session = boto3.session.Session()
        return session.client(
            "logs",
            region_name=config["region"],
            aws_access_key_id=credentials.get("access_key_id"),
            aws_secret_access_key=credentials.get("secret_access_key"),
            aws_session_token=credentials.get("session_token"),
        )

    def _write_internal_error(self, message: str, error: Exception) -> None:
        text = f"{message} {error}" if isinstance(error, BaseException) else f"{message} {error!s}"
        sys.stderr.write(f"[noria-logger] {text}\n")


def create_cloudwatch_destination(
    config: dict[str, Any],
    runtime_context: LoggerRuntimeContext | None = None,
) -> CloudWatchDestination:
    return CloudWatchDestination(config, runtime_context or create_logger_runtime_context())


def _extract_timestamp(message: str) -> int:
    try:
        parsed = json.loads(message)
        time = parsed.get("time")
        timestamp = parsed.get("timestamp")
        if isinstance(time, int):
            return time
        if isinstance(time, str):
            return _parse_timestamp(time)
        if isinstance(timestamp, str):
            return _parse_timestamp(timestamp)
    except Exception:
        pass
    return time_ns() // 1_000_000


def _parse_timestamp(value: str) -> int:
    from datetime import datetime

    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)


def _is_aws_exists_error(error: Exception) -> bool:
    if isinstance(error, ClientError):
        return error.response.get("Error", {}).get("Code") == "ResourceAlreadyExistsException"
    return getattr(error, "name", None) == "ResourceAlreadyExistsException"
