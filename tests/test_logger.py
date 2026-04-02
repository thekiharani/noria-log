from __future__ import annotations

import io
import json
import sys
import time
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from noria_log import cloudwatch as cloudwatch_module
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
from noria_log import file as file_module
from noria_log import logger as logger_module
from noria_log.cloudwatch import CloudWatchDestination, QueuedLogEvent
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
    default_matcher = create_redact_matcher()
    replace_matcher = create_redact_matcher({"keys": ["session_id"], "mode": "replace"})
    merged_matcher = create_redact_matcher(["session_id"])
    assert default_matcher("token") is True
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
    with pytest.raises(ValueError, match="Unsupported rotation mode"):
        format_date_stamp(timestamp, mode="hourly")


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
    assert resolve_target(None, context, {"identifier": "worker-1"}) == "worker-1"


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


def test_create_service_logger_respects_levels_and_supports_all_level_methods(tmp_path: Path):
    file_path = tmp_path / "levels.log"
    bundle = create_service_logger(
        service_name="test-service",
        level="warn",
        destinations=["file"],
        file={"target": {"value": str(file_path)}},
    )
    bundle.logger.trace("trace")
    bundle.logger.debug("debug")
    bundle.logger.info("info")
    bundle.logger.warn("warn")
    bundle.logger.warning("warning")
    bundle.logger.error("error")
    bundle.logger.fatal("fatal")
    bundle.flush()
    bundle.close()
    records = [json.loads(line) for line in file_path.read_text().splitlines()]
    assert [record["msg"] for record in records] == ["warn", "warning", "error", "fatal"]
    assert [record["level"] for record in records] == ["warn", "warn", "error", "fatal"]


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


def test_create_service_logger_supports_base_fields_error_aliases_and_epoch_time_mode(
    tmp_path: Path,
):
    file_path = tmp_path / "base.log"
    bundle = create_service_logger(
        service_name="test-service",
        destinations=["file"],
        schema={"errorKey": "problem", "timeMode": "epoch"},
        base={"component": "worker"},
        file={"target": {"value": str(file_path)}},
    )
    bundle.logger.error("boom", error={"message": "direct"})
    bundle.close()
    parsed = json.loads(file_path.read_text().strip())
    assert parsed["component"] == "worker"
    assert parsed["problem"] == {"message": "direct"}
    assert "time" in parsed
    assert "timestamp" not in parsed


def test_exception_includes_traceback_by_default(tmp_path: Path):
    file_path = tmp_path / "exc.log"
    bundle = create_service_logger(
        service_name="test-service",
        destinations=["file"],
        file={"target": {"value": str(file_path)}},
    )
    try:
        raise ValueError("something broke")
    except ValueError as exc:
        bundle.logger.exception("operation failed", exc, request_id="abc")
    bundle.close()
    parsed = json.loads(file_path.read_text().strip())
    assert parsed["err"]["message"] == "something broke"
    assert "stack" in parsed
    assert "ValueError: something broke" in parsed["stack"]
    assert "test_exception_includes_traceback_by_default" in parsed["stack"]
    assert parsed["request_id"] == "abc"


def test_exception_omits_traceback_when_exc_info_false(tmp_path: Path):
    file_path = tmp_path / "exc_no_tb.log"
    bundle = create_service_logger(
        service_name="test-service",
        destinations=["file"],
        file={"target": {"value": str(file_path)}},
    )
    try:
        raise RuntimeError("no trace please")
    except RuntimeError as exc:
        bundle.logger.exception("op failed", exc, exc_info=False)
    bundle.close()
    parsed = json.loads(file_path.read_text().strip())
    assert parsed["err"]["message"] == "no trace please"
    assert "stack" not in parsed


def test_create_service_logger_validates_destination_configuration_and_supports_stderr(monkeypatch):
    stderr_buffer = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stderr_buffer)
    stdout_buffer = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stdout_buffer)
    stderr_bundle = create_service_logger(service_name="test-service", destinations=["stderr"])
    stdout_bundle = create_service_logger(service_name="test-service", destinations=["stdout"])
    stderr_bundle.logger.info("hello stderr")
    stdout_bundle.logger.info("hello stdout")
    stderr_bundle.flush()
    stdout_bundle.flush()
    stderr_bundle.close()
    stdout_bundle.close()
    parsed = json.loads(stderr_buffer.getvalue().strip())
    assert parsed["msg"] == "hello stderr"
    assert json.loads(stdout_buffer.getvalue().strip())["msg"] == "hello stdout"

    with pytest.raises(ValueError, match="file logging requires file configuration"):
        create_service_logger(service_name="test-service", destinations=["file"])

    class Client:
        def put_log_events(self, **kwargs):
            return None

    cloudwatch_bundle = create_service_logger(
        service_name="test-service",
        destinations=["cloudwatch"],
        cloudwatch={
            "client": Client(),
            "region": "eu-west-1",
            "logGroupName": "group",
            "createLogGroup": False,
            "createLogStream": False,
        },
    )
    cloudwatch_bundle.logger.info("hello cloudwatch")
    cloudwatch_bundle.close()

    with pytest.raises(ValueError, match="cloudwatch logging requires cloudwatch configuration"):
        logger_module._create_managed_destination(
            "cloudwatch",
            file=None,
            cloudwatch=None,
            runtime_context=TEST_RUNTIME,
        )
    with pytest.raises(ValueError, match="Unsupported logger destination 'syslog'"):
        logger_module._create_managed_destination(
            "syslog",
            file=None,
            cloudwatch=None,
            runtime_context=TEST_RUNTIME,
        )


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


def test_file_destination_skips_blank_lines_and_falls_back_to_timestamp_sources(
    tmp_path: Path, monkeypatch
):
    destination = create_file_destination(
        {"target": {"value": str(tmp_path / "fallback.log")}},
        TEST_RUNTIME,
    )
    destination.emit_line("   ")
    destination.emit_line('{"timestamp":"2024-01-01T00:00:00.000Z","msg":"from-timestamp"}')

    monkeypatch.setattr(file_module, "time_ns", lambda: 1_700_000_000_000_000_000, raising=False)
    destination.emit_line("not json at all")
    destination.close()

    lines = (tmp_path / "fallback.log").read_text().splitlines()
    assert json.loads(lines[0])["msg"] == "from-timestamp"
    assert lines[1] == "not json at all"


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


def test_cloudwatch_destination_flushes_immediately_on_batch_limit_and_handles_non_string_lines():
    commands = []

    class Client:
        def put_log_events(self, **kwargs):
            commands.append(kwargs)

    destination = create_cloudwatch_destination(
        {
            "client": Client(),
            "region": "eu-west-1",
            "logGroupName": "group",
            "stream": {"value": "stream"},
            "createLogGroup": False,
            "createLogStream": False,
            "maxBatchCount": 1,
        },
        TEST_RUNTIME,
    )
    destination.emit_line('{"time":1,"msg":"hello"}')
    destination.emit_line("   ")
    assert commands[0]["logEvents"][0]["message"] == '{"time":1,"msg":"hello"}'

    class BadLine:
        def strip(self):
            raise RuntimeError("bad strip")

    with pytest.raises(ValueError, match="bad strip"):
        destination.emit_line(BadLine())  # type: ignore[arg-type]

    destination.close()


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


def test_cloudwatch_destination_covers_timer_batching_and_error_helpers(monkeypatch):
    timer_events = []

    class FakeTimer:
        def __init__(self, interval, callback):
            self.interval = interval
            self.callback = callback
            self.daemon = False
            self.cancelled = False

        def start(self):
            timer_events.append(("started", self.interval))

        def cancel(self):
            self.cancelled = True
            timer_events.append(("cancelled", self.interval))

    monkeypatch.setattr(cloudwatch_module.threading, "Timer", FakeTimer)

    class Client:
        def put_log_events(self, **kwargs):
            return None

    destination = create_cloudwatch_destination(
        {
            "client": Client(),
            "region": "eu-west-1",
            "logGroupName": "group",
            "stream": {"value": "stream"},
            "createLogGroup": False,
            "createLogStream": False,
            "flushIntervalMs": 50,
        },
        TEST_RUNTIME,
    )
    destination.emit_line('{"time":"2024-01-01T00:00:00.000Z","msg":"scheduled"}')
    assert timer_events[0] == ("started", 0.05)
    destination._timer_flush()
    destination.close()

    destination._flush_in_flight = True
    destination.flush()
    destination._flush_in_flight = False

    destination._timer = FakeTimer(1, lambda: None)  # type: ignore[arg-type]
    destination._clear_timer()
    destination._timer = FakeTimer(1, lambda: None)  # type: ignore[arg-type]
    destination._closed = True
    destination._schedule_flush(1)
    assert ("cancelled", 1) in timer_events

    queued = create_cloudwatch_destination(
        {
            "client": Client(),
            "region": "eu-west-1",
            "logGroupName": "group",
            "stream": {"value": "ignored"},
            "createLogGroup": False,
            "createLogStream": False,
            "maxBatchCount": 10,
            "maxBatchBytes": 80,
        },
        TEST_RUNTIME,
    )
    queued._queue = [
        QueuedLogEvent("one", 1, 30, "a"),
        QueuedLogEvent("two", 2, 30, "b"),
        QueuedLogEvent("three", 3, 60, "a"),
    ]
    queued._queue_bytes = 120
    batch = queued._take_batch()
    assert [entry.message for entry in batch] == ["one"]

    error_response = {"Error": {"Code": "ResourceAlreadyExistsException"}}
    client_error = ClientError(error_response, "CreateLogGroup")
    assert cloudwatch_module._is_aws_exists_error(client_error) is True
    non_matching_client_error = ClientError({"Error": {"Code": "Other"}}, "CreateLogGroup")
    assert cloudwatch_module._is_aws_exists_error(non_matching_client_error) is False

    class NamedError(Exception):
        name = "ResourceAlreadyExistsException"

    assert cloudwatch_module._is_aws_exists_error(NamedError("exists")) is True
    assert cloudwatch_module._is_aws_exists_error(RuntimeError("nope")) is False


def test_cloudwatch_destination_validates_retention_and_resource_creation_errors():
    class GroupErrorClient:
        def create_log_group(self, **kwargs):
            raise RuntimeError("group failed")

    destination = create_cloudwatch_destination(
        {
            "client": GroupErrorClient(),
            "region": "eu-west-1",
            "logGroupName": "group",
        },
        TEST_RUNTIME,
    )
    with pytest.raises(RuntimeError, match="group failed"):
        destination._ensure_log_group()

    class RetentionClient:
        def create_log_group(self, **kwargs):
            return None

    invalid_retention = create_cloudwatch_destination(
        {
            "client": RetentionClient(),
            "region": "eu-west-1",
            "logGroupName": "group",
            "retentionInDays": 2,
        },
        TEST_RUNTIME,
    )
    with pytest.raises(ValueError, match="Unsupported CloudWatch retentionInDays '2'"):
        invalid_retention._ensure_log_group()

    class StreamErrorClient:
        def create_log_stream(self, **kwargs):
            raise RuntimeError("stream failed")

    stream_destination = create_cloudwatch_destination(
        {
            "client": StreamErrorClient(),
            "region": "eu-west-1",
            "logGroupName": "group",
        },
        TEST_RUNTIME,
    )
    with pytest.raises(RuntimeError, match="stream failed"):
        stream_destination._ensure_log_stream("stream")


def test_cloudwatch_destination_extracts_timestamps_from_timestamp_field():
    commands = []

    class Client:
        def put_log_events(self, **kwargs):
            commands.append(kwargs)

    destination = create_cloudwatch_destination(
        {
            "client": Client(),
            "region": "eu-west-1",
            "logGroupName": "group",
            "stream": {"value": "stream"},
            "createLogGroup": False,
            "createLogStream": False,
            "maxBatchCount": 1,
        },
        TEST_RUNTIME,
    )
    destination.emit_line('{"timestamp":"2024-01-01T00:00:00.000Z","msg":"hello"}')
    destination.close()
    assert commands[0]["logEvents"][0]["timestamp"] == 1704067200000


def test_cloudwatch_destination_builds_boto_client_with_credentials(monkeypatch):
    calls = []

    class Session:
        def client(self, service_name, **kwargs):
            calls.append((service_name, kwargs))
            return object()

    monkeypatch.setattr(cloudwatch_module.boto3.session, "Session", lambda: Session())
    destination = CloudWatchDestination(
        {
            "region": "eu-west-1",
            "logGroupName": "group",
            "credentials": {
                "access_key_id": "key",
                "secret_access_key": "secret",
                "session_token": "token",
            },
        },
        TEST_RUNTIME,
    )
    assert destination._client is not None
    assert calls == [
        (
            "logs",
            {
                "region_name": "eu-west-1",
                "aws_access_key_id": "key",
                "aws_secret_access_key": "secret",
                "aws_session_token": "token",
            },
        )
    ]


def test_create_service_logger_supports_stdout_destination_without_closing_standard_streams(
    monkeypatch,
):
    buffer = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buffer)
    destination = StdDestination(sys.stdout)
    destination.emit_line("hello")
    destination.flush()
    destination.close()
    assert buffer.getvalue() == "hello\n"
