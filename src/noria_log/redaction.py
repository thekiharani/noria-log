from __future__ import annotations

import re
import traceback
from collections.abc import Callable, Iterable
from typing import Any

DEFAULT_SENSITIVE_KEY_PATTERN = re.compile(
    r"(token|secret|key|password|passkey|authorization|dsn|credential|api_key)",
    re.IGNORECASE,
)

RedactMatcher = Callable[[str], bool]


def create_redact_matcher(config: dict[str, Any] | Iterable[str] | None = None) -> RedactMatcher:
    if config is None:
        resolved_keys: list[str] = []
        mode = "merge"
    elif isinstance(config, dict):
        resolved_keys = [
            str(entry).strip().lower() for entry in config.get("keys", []) if str(entry).strip()
        ]
        mode = config.get("mode", "merge")
    else:
        resolved_keys = [str(entry).strip().lower() for entry in config if str(entry).strip()]
        mode = "merge"

    exact_keys = set(resolved_keys)

    def should_redact(key: str) -> bool:
        return (
            mode == "merge" and bool(DEFAULT_SENSITIVE_KEY_PATTERN.search(key))
        ) or key.lower() in exact_keys

    return should_redact


def sanitize_log_value(value: Any, should_redact: RedactMatcher) -> Any:
    if isinstance(value, BaseException):
        return {
            "name": value.__class__.__name__,
            "message": str(value),
            "stack": "".join(traceback.format_exception(value)).rstrip(),
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_log_value(entry, should_redact) for entry in value]
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if should_redact(key) else sanitize_log_value(entry, should_redact)
            for key, entry in value.items()
        }
    return value


def parse_comma_separated_list(raw_value: str | None = None) -> list[str]:
    if raw_value is None or not raw_value.strip():
        return []
    return list(dict.fromkeys(entry.strip() for entry in raw_value.split(",") if entry.strip()))
