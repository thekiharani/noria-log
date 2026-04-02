from __future__ import annotations

import json
from pathlib import Path
from typing import TextIO

from .targets import LoggerRuntimeContext, create_logger_target_context, resolve_target


class FileDestination:
    def __init__(self, config: dict[str, object], runtime_context: LoggerRuntimeContext) -> None:
        self._config = config
        self._runtime_context = runtime_context
        self._streams: dict[str, TextIO] = {}

    def emit_line(self, line: str, *, timestamp_ms: int | None = None) -> None:
        stripped = line.strip()
        if not stripped:
            return
        timestamp = timestamp_ms if timestamp_ms is not None else _extract_timestamp(stripped)
        path = resolve_target(
            self._config.get("target") if isinstance(self._config.get("target"), dict) else None,
            create_logger_target_context(self._runtime_context, timestamp),
            {"value": ""},
        )
        if not path:
            raise ValueError(
                "file logging requires file.target.value, "
                "file.target.prefix, or file.target.resolve."
            )
        stream = self._get_stream(path)
        stream.write(f"{stripped}\n")

    def flush(self) -> None:
        for stream in self._streams.values():
            stream.flush()

    def close(self) -> None:
        self.flush()
        for stream in self._streams.values():
            stream.close()
        self._streams.clear()

    def _get_stream(self, path: str) -> TextIO:
        existing = self._streams.get(path)
        if existing is not None:
            return existing
        if self._config.get("mkdir", True):
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        stream = Path(path).open("a", encoding="utf-8")  # noqa: SIM115
        self._streams[path] = stream
        return stream


def create_file_destination(
    config: dict[str, object], runtime_context: LoggerRuntimeContext
) -> FileDestination:
    return FileDestination(config, runtime_context)


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
    from time import time_ns

    return time_ns() // 1_000_000


def _parse_timestamp(value: str) -> int:
    from datetime import datetime

    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)
