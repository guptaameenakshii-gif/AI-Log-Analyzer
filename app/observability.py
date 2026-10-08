import ipaddress
import os
import re
import threading

from langfuse import Langfuse


_REDACTED = "[REDACTED]"
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|secret(?:_key)?|api[_-]?key|"
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|token|"
    r"authorization|credential|client_secret)\b"
    r"(\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"
)
_KNOWN_SECRET = re.compile(
    r"\b(?:gsk_[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9_-]{16,}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b"
)
_IPV4_CANDIDATE = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
)
_IPV6_CANDIDATE = re.compile(
    r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])"
)
_USERNAME_ASSIGNMENT = re.compile(
    r"(?i)\b(user(?:name)?|account|principal|actor|owner)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
_SENSITIVE_KEYS = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|token|"
    r"authorization|credential|private[_-]?key|cookie)"
)

_client = None
_client_lock = threading.Lock()


def _enabled(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _mask_ip_candidates(text: str, pattern: re.Pattern) -> str:
    def replace(match):
        candidate = match.group(0)
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return candidate
        return _REDACTED

    return pattern.sub(replace, text)


def _mask_string(value: str) -> str:
    value = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{_REDACTED}",
        value,
    )
    value = _BEARER_TOKEN.sub(f"Bearer {_REDACTED}", value)
    value = _JWT.sub(_REDACTED, value)
    value = _KNOWN_SECRET.sub(_REDACTED, value)

    if _enabled("LANGFUSE_REDACT_USERNAMES"):
        value = _USERNAME_ASSIGNMENT.sub(
            lambda match: f"{match.group(1)}{match.group(2)}{_REDACTED}",
            value,
        )

    if _enabled("LANGFUSE_REDACT_IPS"):
        value = _mask_ip_candidates(value, _IPV4_CANDIDATE)
        value = _mask_ip_candidates(value, _IPV6_CANDIDATE)

    return value


def mask_sensitive_data(*, data, **kwargs):
    """Mask secrets in Langfuse payloads, with optional identity/IP masking."""

    if isinstance(data, str):
        return _mask_string(data)

    if isinstance(data, dict):
        masked = {}
        for key, value in data.items():
            if isinstance(key, str) and _SENSITIVE_KEYS.search(key):
                masked[key] = _REDACTED
            else:
                masked[key] = mask_sensitive_data(data=value)
        return masked

    if isinstance(data, list):
        return [mask_sensitive_data(data=value) for value in data]

    if isinstance(data, tuple):
        return tuple(mask_sensitive_data(data=value) for value in data)

    return data


def get_langfuse_client():
    """Return the shared v4 client configured with the payload mask."""

    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = Langfuse(mask=mask_sensitive_data)
    return _client
