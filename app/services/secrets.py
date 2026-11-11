"""Resolve external secret references without persisting secret material in connector records."""

import os
import re
import stat
from pathlib import Path


def resolve_secret_reference(reference: str | None) -> str | None:
    if not reference:
        return None
    if reference.startswith("env://"):
        name = reference[6:]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError("Environment secret reference is invalid")
        value = os.getenv(name)
        if not value:
            raise ValueError("Referenced environment secret is unavailable")
        return value

    if reference.startswith("file://"):
        raw_path = Path(reference[7:])
        if not raw_path.is_absolute() or raw_path.is_symlink() or ".." in raw_path.parts:
            raise ValueError("File secret reference must be an absolute, non-symlink path")
        try:
            resolved = raw_path.resolve(strict=True)
        except OSError as exc:
            raise ValueError("Referenced file secret is unavailable") from exc
        allowed_roots = (Path("/run/secrets").resolve(), Path("/var/run/secrets").resolve())
        if not any(resolved == root or root in resolved.parents for root in allowed_roots):
            raise ValueError("File secrets are restricted to the mounted runtime secrets directories")
        if not resolved.is_file():
            raise ValueError("File secret reference must identify a regular file")
        mode = stat.S_IMODE(resolved.stat().st_mode)
        if mode & 0o077:
            raise ValueError("File secret permissions must not grant group or world access")
        if resolved.stat().st_size > 65536:
            raise ValueError("File secret exceeds the 64 KiB limit")
        value = resolved.read_text(encoding="utf-8").strip()
        if not value:
            raise ValueError("Referenced file secret is empty")
        return value

    raise ValueError("Secret reference must use env://NAME or file:///run/secrets/NAME")
