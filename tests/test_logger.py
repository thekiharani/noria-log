from __future__ import annotations

import io
import json
import sys
import time
from pathlib import Path

import pytest

from noria_log import (
    create_cloudwatch_destination,
    create_file_destination,
    create_logger_runtime_context,
    create_redact_matcher,
    create_service_logger,
    format_date_stamp,
    parse_logger_destinations,
    parse_logger_redact_keys,
    resolve_target,
    sanitize_log_value,
)
from noria_log.logger import StdDestination
from noria_log.targets import create_logger_target_context

TEST_RUNTIME = create_logger_runtime_context(
    service_name="test-service",
    environment="test",
    hostname="logger-host",
    instance_id="instance-a",
    pid=4321,
)


def test_parse_logger_destinations_parses_defaults_and_deduplicates_entries():
    assert parse_logger_destinations() == ["stdout"]
    assert parse_logger_destinations("stdout, cloudwatch, stdout") == ["stdout", "cloudwatch"]
    with pytest.raises(ValueError, match="Unsupported logger destination"):
        parse_logger_destinations("stdout,unknown")


def test_parse_logger_redact_keys_parses_comma_separated_values():
    assert parse_logger_redact_keys("authorization, api_key, authorization") == [
        "authorization",
        "api_key",
    ]


def test_sanitize_log_value_redacts_secrets_recursively():
    error = RuntimeError("boom")
    sanitized = sanitize_log_value(
        {
            "api_key": "secret",
            "nested": {"password": "secret-2", "ok": "value"},
            "list": [error, {"token": "secret-3"}],
        },
        lambda key: key.lower() in {"api_key", "password", "token"},
    )
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["nested"]["password"] == "[REDACTED]"
    assert sanitized["nested"]["ok"] == "value"
    assert sanitized["list"][0]["message"] == "boom"
    assert sanitized["list"][1]["token"] == "[REDACTED]"


def test_create_redact_matcher_supports_replace_and_merge_modes():
    replace_matcher = create_redact_matcher({"keys": ["session_id"], "mode": "replace"})
    merged_matcher = create_redact_matcher(["session_id"])
    assert replace_matcher("session_id") is True
    assert replace_matcher("token") is False
    assert merged_matcher("session_id") is True
    assert merged_matcher("token") is True


def test_format_date_stamp_supports_daily_monthly_annual_and_timezone_aware_formatting():
    timestamp = 1704164645000
    assert format_date_stamp(timestamp, mode="none") == ""
    assert format_date_stamp(timestamp, mode="daily") == "2024-01-02"
    assert format_date_stamp(timestamp, mode="monthly") == "2024-01"
    assert format_date_stamp(timestamp, mode="annual") == "2024"
    assert format_date_stamp(timestamp, mode="daily", timezone="America/New_York") == "2024-01-01"


def test_resolve_target_supports_defaults_rotations_custom_separators_and_custom_resolvers():
    timestamp = 1711578600000
    context = create_logger_target_context(TEST_RUNTIME, timestamp)
    assert resolve_target(None, context, {"value": "fallback"}) == "fallback"
    assert resolve_target({"value": "fixed"}, context) == "fixed"
    assert (
        resolve_target(
            {
                "prefix": "logs",
                "rotation": "monthly",
                "includeServiceName": True,
                "includeEnvironment": True,
                "includeHostname": True,
                "includePid": True,
                "suffix": ".jsonl",
                "separator": "/",
            },
            context,
        )
        == "logs/2024-03/test-service/test/logger-host/4321.jsonl"
    )
    assert (
        resolve_target({"prefix": "logs", "rotation": "daily", "includeInstanceId": True}, context)
        == "logs-2024-03-27-instance-a"
    )
    assert (
        resolve_target(
            {"resolve": lambda target_context: f"{target_context.service_name}-2024"}, context
        )
        == "test-service-2024"
    )


def test_create_service_logger_rejects_duplicate_timestamp_keys():
    with pytest.raises(ValueError, match="schema.timeKey and schema.timestampKey must differ"):
        create_service_logger(
            service_name="test-service",
            schema={"timeKey": "timestamp", "timestampKey": "timestamp", "timeMode": "both"},
        )


def test_create_service_logger_merges_redact_keys_and_writes_to_file(tmp_path: Path):
    file_path = tmp_path / "service.log"
    bundle = create_service_logger(
        service_name="test-service",
        destinations=["file"],
        redact_keys=["session_id"],
        redact={},
        file={"target": {"value": str(file_path)}},
    )
    bundle.logger.info("hello", session_id="hidden", token="secret")
    bundle.close()
    parsed = json.loads(file_path.read_text().strip())
    assert parsed["session_id"] == "[REDACTED]"
    assert parsed["token"] == "[REDACTED]"


def test_create_service_logger_supports_schema_remapping_identity_overrides_and_redaction(
    tmp_path: Path,
):
    file_path = tmp_path / "custom-host-instance-b-9876.log"
    bundle = create_service_logger(
        service_name="test-service",
        environment="test",
        destinations=["file"],
        identity={"hostname": "custom-host", "instanceId": "instance-b", "pid": 9876},
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
        redact={"keys": ["session_id"], "mode": "replace"},
        file={
            "target": {
                "resolve": lambda context: str(
                    tmp_path / f"{context.hostname}-{context.instance_id}-{context.pid}.log"
                )
            }
        },
    )
    bundle.logger.info(
        "hello", token="visible", session_id="hidden", hostname=TEST_RUNTIME.hostname
    )
    bundle.logger.error("broken", err=RuntimeError("boom"))
    bundle.close()
    lines = file_path.read_text().strip().splitlines()
    first = json.loads(lines[0])
    second = json.loads(lines[1])
    assert first["severity"] == "info"
    assert first["severityValue"] == 30
    assert first["message"] == "hello"
    assert first["app"] == "test-service"
    assert first["stage"] == "test"
    assert first["token"] == "visible"
    assert first["session_id"] == "[REDACTED]"
    assert "ts" not in first
    assert isinstance(first["tsIso"], str)
    assert second["error"]["message"] == "boom"


def test_file_destination_resolves_dynamic_targets_using_event_timestamps(tmp_path: Path):
    destination = create_file_destination(
        {"target": {"prefix": str(tmp_path / "app"), "rotation": "daily", "suffix": ".log"}},
        TEST_RUNTIME,
    )
    destination.emit_line('{"time":"2024-01-01T23:59:59.000Z","msg":"before"}')
    destination.emit_line('{"time":"2024-01-02T00:00:01.000Z","msg":"after"}')
    destination.close()
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "app-2024-01-01.log",
        "app-2024-01-02.log",
    ]


def test_file_destination_supports_custom_resolvers_and_invalid_targets(tmp_path: Path):
    destination = create_file_destination(
        {
            "target": {
                "resolve": lambda context: str(
                    tmp_path / f"{context.environment}-{context.service_name}.log"
                )
            }
        },
        TEST_RUNTIME,
    )
    destination.emit_line('{"time":"2024-01-01T00:00:00.000Z","msg":"hello"}')
    destination.close()
    content = (tmp_path / "test-test-service.log").read_text()
    assert '"msg":"hello"' in content
    broken = create_file_destination({}, TEST_RUNTIME)
    with pytest.raises(
        ValueError, match="file.target.value, file.target.prefix, or file.target.resolve"
    ):
        broken.emit_line('{"time":1,"msg":"boom"}')


def test_cloudwatch_destination_creates_resources_and_publishes_batched_events():
    commands = []

    class Client:
        def create_log_group(self, **kwargs):
            commands.append(("create_group", kwargs))

        def create_log_stream(self, **kwargs):
            commands.append(("create_stream", kwargs))

        def put_log_events(self, **kwargs):
            commands.append(("put_events", kwargs))

    destination = create_cloudwatch_destination(
        {
            "client": Client(),
            "region": "eu-west-1",
            "logGroupName": "group",
            "stream": {"value": "stream"},
            "flushIntervalMs": 1,
        },
        TEST_RUNTIME,
    )
    destination.emit_line('{"time":1,"msg":"hello"}')
    destination.emit_line('{"time":2,"msg":"world"}')
    destination.close()
    assert commands[0][0] == "create_group"
    assert commands[1][0] == "create_stream"
    assert commands[2][0] == "put_events"
    assert commands[2][1]["logGroupName"] == "group"
    assert commands[2][1]["logStreamName"] == "stream"
    assert len(commands[2][1]["logEvents"]) == 2


def test_cloudwatch_destination_applies_retention_and_retries_after_failures():
    commands = []
    attempts = {"count": 0}

    class Client:
        def create_log_group(self, **kwargs):
            commands.append(("create_group", kwargs))

        def put_retention_policy(self, **kwargs):
            commands.append(("retention", kwargs))

        def create_log_stream(self, **kwargs):
            commands.append(("create_stream", kwargs))

        def put_log_events(self, **kwargs):
            commands.append(("put_events", kwargs))
            if attempts["count"] == 0:
                attempts["count"] += 1
                raise RuntimeError("temporary failure")

    destination = create_cloudwatch_destination(
        {
            "client": Client(),
            "region": "eu-west-1",
            "logGroupName": "group",
            "stream": {"value": "stream"},
            "retentionInDays": 30,
            "flushIntervalMs": 1,
            "retryBaseDelayMs": 1,
        },
        TEST_RUNTIME,
    )
    destination.emit_line('{"time":1,"msg":"hello"}')
    time.sleep(0.02)
    destination.close()
    assert any(entry[0] == "retention" for entry in commands)
    assert len([entry for entry in commands if entry[0] == "put_events"]) >= 2


def test_cloudwatch_destination_supports_rotated_stream_names_and_timezone_aware_rollover():
    commands = []

    class Client:
        def put_log_events(self, **kwargs):
            commands.append(("put_events", kwargs))

    destination = create_cloudwatch_destination(
        {
            "client": Client(),
            "region": "eu-west-1",
            "logGroupName": "group",
            "stream": {
                "prefix": "noria-stream",
                "rotation": "daily",
                "timezone": "America/New_York",
                "includeHostname": False,
                "includePid": False,
            },
            "createLogGroup": False,
            "createLogStream": False,
        },
        TEST_RUNTIME,
    )
    destination.emit_line('{"time":"2024-01-02T03:04:05.000Z","msg":"zoned"}')
    destination.close()
    assert commands[0][1]["logStreamName"] == "noria-stream-2024-01-01"


def test_cloudwatch_destination_uses_hostname_pid_by_default_and_trims_oversized_buffers():
    commands = []

    class Client:
        def put_log_events(self, **kwargs):
            commands.append(kwargs)

    destination = create_cloudwatch_destination(
        {
            "client": Client(),
            "region": "eu-west-1",
            "logGroupName": "group",
            "createLogGroup": False,
            "createLogStream": False,
            "maxBufferedEvents": 1,
            "maxBatchBytes": 60,
        },
        TEST_RUNTIME,
    )
    destination.emit_line("first")
    destination.emit_line("second")
    destination.close()
    assert commands[0]["logStreamName"] == "logger-host-4321"
    assert [event["message"] for event in commands[0]["logEvents"]] == ["second"]


def test_create_service_logger_supports_stdout_destination_without_closing_standard_streams(
    monkeypatch,
):
    buffer = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buffer)
    destination = StdDestination(sys.stdout)
    destination.emit_line("hello")
    destination.close()
    assert buffer.getvalue() == "hello\n"
