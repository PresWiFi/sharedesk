"""NFS exports: parse /etc/exports and /etc/exports.d/*.exports, edit single lines in place,
and apply with `exportfs -ra` (restoring the old file if exportfs rejects the new one)."""
from __future__ import annotations

import difflib
import hashlib
import re
import shlex

from . import validate as v
from .host import Plan, Step

MAIN = "/etc/exports"
MANAGED = "/etc/exports.d/sharedesk.exports"
_CLIENT = re.compile(r"^([^()]*)(?:\((.*)\))?$")


def line_id(file: str, line: int, text: str) -> str:
    return hashlib.sha256(f"{file}\0{line}\0{text}".encode()).hexdigest()[:16]


def parse(file: str, text: str) -> list[dict]:
    """One dict per export line. `line` is the 0-based index of its first physical line."""
    lines = text.split("\n")
    entries, i = [], 0
    while i < len(lines):
        start, buf = i, lines[i]
        while buf.endswith("\\") and i + 1 < len(lines):
            i += 1
            buf = buf[:-1] + " " + lines[i]
        end = i
        i += 1
        content = buf.strip()
        if not content or content.startswith("#"):
            continue
        try:
            tokens = shlex.split(content, comments=True)
        except ValueError:
            tokens = content.split()
        if not tokens:
            continue
        defaults, clients = "", []
        for tok in tokens[1:]:
            if tok.startswith("-"):
                defaults = tok[1:]
                continue
            m = _CLIENT.match(tok)
            host, opts = (m.group(1), m.group(2) or "") if m else (tok, "")
            clients.append({"host": host, "options": opts})
        raw = "\n".join(lines[start:end + 1])
        entries.append({"id": line_id(file, start, raw), "file": file, "line": start, "span": end - start + 1,
                        "raw": raw, "path": tokens[0], "defaults": defaults, "clients": clients})
    return entries


def render(path: str, clients: list[dict]) -> str:
    p = shlex.quote(path) if re.search(r"\s", path) else path
    parts = [f"{c['host']}({c['options']})" if c["options"] else c["host"] for c in clients]
    return f"{p:<26} " + " ".join(parts)


def clean_clients(clients: list[dict]) -> list[dict]:
    out = [{"host": v.nfs_host(c.get("host", "")), "options": v.nfs_options(c.get("options", ""))}
           for c in clients or []]
    if not out:
        raise v.Invalid("An export needs at least one client.")
    return out


def _write_plan(title: str, file: str, old: str | None, new: str) -> Plan:
    backup = file + ".sharedesk-bak"
    diff = "".join(difflib.unified_diff((old or "").splitlines(True), new.splitlines(True),
                                        fromfile=file, tofile=file))
    steps, rollback = [], []
    if old is not None:
        steps.append(Step(["cp", "-a", "--", file, backup], f"Back up {file}"))
        rollback = [Step(["cp", "-a", "--", backup, file], f"Restore {file}")]
    else:
        rollback = [Step(["tee", file], f"Empty {file}", input="", show_input=True)]
    steps += [Step(["tee", file], f"Write {file}", input=new, show_input=True),
              Step(["exportfs", "-ra"], "Re-export everything")]
    rollback.append(Step(["exportfs", "-ra"], "Re-export the old config"))
    return Plan(title, steps, rollback, diff)


def _find(entries: list[dict], file: str, entry_id: str) -> dict:
    for e in entries:
        if e["file"] == file and e["id"] == entry_id:
            return e
    raise v.Invalid("That export line changed on the server since you loaded it. Reload and try again.")


def update(file: str, text: str, entry_id: str, path: str, clients: list[dict]) -> Plan:
    e = _find(parse(file, text), file, entry_id)
    path = v.abs_path(path)
    new_line = render(path, clean_clients(clients))
    lines = text.split("\n")
    lines[e["line"]:e["line"] + e["span"]] = [new_line]
    return _write_plan(f"Update NFS export {path}", file, text, "\n".join(lines))


def delete(file: str, text: str, entry_id: str) -> Plan:
    e = _find(parse(file, text), file, entry_id)
    lines = text.split("\n")
    del lines[e["line"]:e["line"] + e["span"]]
    return _write_plan(f"Remove NFS export {e['path']}", file, text, "\n".join(lines))


def add(text: str | None, path: str, clients: list[dict], share_root: str, all_entries: list[dict]) -> Plan:
    path = v.under_root(path, share_root)
    if any(e["path"] == path for e in all_entries):
        raise v.Invalid(f"{path} is already exported; edit the existing line instead.")
    line = render(path, clean_clients(clients))
    body = text or "# Managed by ShareDesk\n"
    if not body.endswith("\n"):
        body += "\n"
    return _write_plan(f"Add NFS export {path}", MANAGED, text, body + line + "\n")
