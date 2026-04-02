from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from os import getpid
from socket import gethostname
from zoneinfo import ZoneInfo


@dataclass(slots=True)
class LoggerRuntimeContext:
    service_name: str | None
    environment: str | None
    hostname: str
    pid: int
    instance_id: str | None = None


@dataclass(slots=True)
class LoggerTargetContext(LoggerRuntimeContext):
    timestamp: int = 0
    iso_timestamp: str = ""


def create_logger_runtime_context(
    *,
    service_name: str | None = None,
    environment: str | None = None,
    hostname: str | None = None,
    pid: int | None = None,
    instance_id: str | None = None,
) -> LoggerRuntimeContext:
    return LoggerRuntimeContext(
        service_name=service_name,
        environment=environment,
        hostname=hostname or gethostname(),
        pid=pid or getpid(),
        instance_id=instance_id,
    )


def create_logger_target_context(
    runtime: LoggerRuntimeContext, timestamp: int
) -> LoggerTargetContext:
    return LoggerTargetContext(
        service_name=runtime.service_name,
        environment=runtime.environment,
        hostname=runtime.hostname,
        pid=runtime.pid,
        instance_id=runtime.instance_id,
        timestamp=timestamp,
        iso_timestamp=_iso_timestamp(timestamp),
    )


def format_date_stamp(timestamp: int, *, mode: str, timezone: str | None = None) -> str:
    if mode == "none":
        return ""
    dt = datetime.fromtimestamp(timestamp / 1000, tz=ZoneInfo(timezone or "UTC"))
    if mode == "annual":
        return dt.strftime("%Y")
    if mode == "monthly":
        return dt.strftime("%Y-%m")
    if mode == "daily":
        return dt.strftime("%Y-%m-%d")
    raise ValueError(f"Unsupported rotation mode '{mode}'.")


def resolve_target(
    target: dict[str, object] | None,
    context: LoggerTargetContext,
    defaults: dict[str, object] | None = None,
) -> str:
    defaults = defaults or {}
    if target and callable(target.get("resolve")):
        return target["resolve"](context)  # type: ignore[misc]
    if target and target.get("value"):
        return str(target["value"])
    separator = str((target or {}).get("separator") or defaults.get("separator") or "-")
    parts: list[str] = []
    prefix = (target or {}).get("prefix") or defaults.get("value")
    if prefix:
        parts.append(str(prefix))
    rotation = str((target or {}).get("rotation") or "none")
    if rotation != "none":
        parts.append(
            format_date_stamp(
                context.timestamp,
                mode=rotation,
                timezone=(target or {}).get("timezone"),
            )
        )
    include_service_name = bool(
        (target or {}).get("includeServiceName", defaults.get("includeServiceName", False))
    )
    include_environment = bool(
        (target or {}).get("includeEnvironment", defaults.get("includeEnvironment", False))
    )
    include_hostname = bool(
        (target or {}).get("includeHostname", defaults.get("includeHostname", False))
    )
    include_instance_id = bool(
        (target or {}).get("includeInstanceId", defaults.get("includeInstanceId", False))
    )
    include_pid = bool((target or {}).get("includePid", defaults.get("includePid", False)))
    identifier = (target or {}).get("identifier") or defaults.get("identifier")
    if include_service_name and context.service_name:
        parts.append(context.service_name)
    if include_environment and context.environment:
        parts.append(context.environment)
    if include_hostname:
        parts.append(context.hostname)
    if include_instance_id and context.instance_id:
        parts.append(context.instance_id)
    if include_pid:
        parts.append(str(context.pid))
    if identifier:
        parts.append(str(identifier))
    suffix = str((target or {}).get("suffix") or "")
    return f"{separator.join(part for part in parts if part)}{suffix}"


def _iso_timestamp(timestamp: int) -> str:
    return (
        datetime.fromtimestamp(timestamp / 1000, tz=UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
