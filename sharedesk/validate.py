"""Input checks. Commands are always passed as argv lists and shell-quoted, so these guard
against bad values (and Samba/exports syntax breakage), not shell injection."""
from __future__ import annotations

import posixpath
import re


class Invalid(ValueError):
    pass


_NAME = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}\$?$")
_SHARE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.$-]{0,79}$")
_PARAM = re.compile(r"^[a-z][a-z0-9 :_]{0,63}$")
_MODE = re.compile(r"^[0-7]{3,4}$")
_NFS_HOST = re.compile(r"^[A-Za-z0-9.*?:/\[\]@_-]{1,255}$")
_NFS_OPTS = re.compile(r"^[A-Za-z0-9_=,:./@-]{0,512}$")
RESERVED_SHARES = {"global", "homes", "printers", "print$"}


def account(name: str, what: str = "name") -> str:
    name = (name or "").strip()
    if not _NAME.match(name):
        raise Invalid(f"Invalid {what} '{name}': use lowercase letters, digits, _ . - (max 32).")
    return name


def owner(name: str, what: str) -> str:
    name = (name or "").strip()
    if name.isdigit():
        return name
    return account(name, what)


def share_name(name: str) -> str:
    name = (name or "").strip()
    if not _SHARE.match(name) or name.lower() in RESERVED_SHARES:
        raise Invalid(f"Invalid share name '{name}'.")
    return name


def param_key(key: str) -> str:
    key = " ".join((key or "").strip().lower().split())
    if not _PARAM.match(key):
        raise Invalid(f"Invalid Samba parameter '{key}'.")
    return key


def param_value(value: str) -> str:
    value = "" if value is None else str(value).strip()
    if "\n" in value or "\r" in value or len(value) > 1024:
        raise Invalid("Samba parameter values must be a single line.")
    return value


def mode(value: str) -> str:
    value = (value or "").strip()
    if not _MODE.match(value):
        raise Invalid(f"Invalid mode '{value}': use octal like 2775.")
    return value.zfill(4)


def password(value: str) -> str:
    if not value or len(value) < 8:
        raise Invalid("Passwords must be at least 8 characters.")
    if "\n" in value or "\r" in value:
        raise Invalid("Passwords can't contain line breaks.")
    return value


def abs_path(path: str) -> str:
    path = (path or "").strip()
    if not path.startswith("/") or "\n" in path or "\x00" in path:
        raise Invalid(f"'{path}' must be an absolute path.")
    return posixpath.normpath(path)


def under_root(path: str, root: str) -> str:
    """Lexical check; callers also resolve symlinks on the host (see folders.resolve)."""
    path = abs_path(path)
    root = posixpath.normpath(root)
    if path != root and not path.startswith(root + "/"):
        raise Invalid(f"'{path}' is outside {root}.")
    return path


def nfs_host(value: str) -> str:
    value = (value or "").strip()
    if not _NFS_HOST.match(value):
        raise Invalid(f"Invalid NFS client '{value}'.")
    return value


def nfs_options(value: str) -> str:
    value = (value or "").strip().replace(" ", "")
    if not _NFS_OPTS.match(value):
        raise Invalid(f"Invalid NFS options '{value}'.")
    return value
