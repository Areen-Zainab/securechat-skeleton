"""
Common utility functions for encoding, hashing, and timestamps.
"""

import base64
import hashlib
import time


def b64encode(data: bytes) -> str:
    """Encode bytes to base64 string."""
    return base64.b64encode(data).decode('utf-8')


def b64decode(data: str) -> bytes:
    """Decode base64 string to bytes."""
    return base64.b64decode(data)


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hash and return as hex string."""
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    """Compute SHA-256 hash and return as bytes."""
    return hashlib.sha256(data).digest()


def now_ms() -> int:
    """Get current timestamp in milliseconds."""
    return int(time.time() * 1000)


def format_timestamp(ts_ms: int) -> str:
    """Format millisecond timestamp to readable string."""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_ms / 1000))