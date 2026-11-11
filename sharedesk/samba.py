"""Samba shares (registry config via `net conf`), Samba users (pdbedit/smbpasswd) and Unix groups."""
from __future__ import annotations

import re

from . import validate as v
from .host import Plan, Step

RELOAD = Step(["smbcontrol", "smbd", "reload-config"], "Tell smbd to reload its config", ok_codes=(0, 1))


def parse_conf(text: str) -> dict[str, dict[str, str]]:
    """Parse `net conf list` output into {section: {param: value}}, keeping order."""
    sections: dict[str, dict[str, str]] = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        m = re.match(r"^\[(.+)\]$", line)
        if m:
            current = sections.setdefault(m.group(1), {})
        elif current is not None and "=" in line:
            key, _, value = line.partition("=")
            current[" ".join(key.strip().lower().split())] = value.strip()
    return sections


def uses_registry(global_params: dict[str, str]) -> bool:
    """True if smb.conf reads shares from the registry, which is where `net conf` writes them."""
    return (global_params.get("include", "").lower() == "registry"
            or global_params.get("config backend", "").lower() == "registry")


def share_plan(name: str, current: dict[str, str], desired: dict[str, str]) -> list[Step]:
    """Steps that turn one share's current params into the desired ones."""
    steps = []
    for key in current:
        if key not in desired:
            steps.append(Step(["net", "conf", "delparm", name, key], f"Remove '{key}'"))
    for key, value in desired.items():
        if current.get(key) != value:
            steps.append(Step(["net", "conf", "setparm", name, key, value], f"Set '{key}' = {value}"))
    return steps


def clean_params(params: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in (params or {}).items():
        value = v.param_value(value)
        if value != "":
            out[v.param_key(key)] = value
    return out


def update_share(name: str, current: dict[str, str], params: dict, share_root: str) -> Plan:
    desired = clean_params(params)
    if "path" not in desired:
        raise v.Invalid("A share needs a path.")
    if desired["path"] != current.get("path"):
        desired["path"] = v.under_root(desired["path"], share_root)
    steps = share_plan(name, current, desired)
    if not steps:
        raise v.Invalid("Nothing changed.")
    return Plan(f"Update SMB share [{name}]", steps + [RELOAD])


def create_share(name: str, params: dict, share_root: str, existing: set[str],
                 mkdir: dict | None) -> Plan:
    name = v.share_name(name)
    if name.lower() in {s.lower() for s in existing}:
        raise v.Invalid(f"Share [{name}] already exists.")
    desired = clean_params(params)
    path = v.under_root(desired.get("path", ""), share_root)
    if path == share_root:
        raise v.Invalid("Pick a folder inside the share root, not the root itself.")
    desired["path"] = path
    steps = []
    if mkdir:
        owner = v.owner(mkdir.get("owner") or "root", "owner")
        group = v.owner(mkdir.get("group") or "root", "group")
        mode = v.mode(mkdir.get("mode") or "2775")
        steps += [
            Step(["mkdir", "-p", "--", path], f"Create folder {path}"),
            Step(["chown", f"{owner}:{group}", "--", path], f"Set owner {owner}:{group}"),
            Step(["chmod", "0" + mode, "--", path], f"Set mode {mode}"),
        ]
    # addshare needs path + writeable/guest flags; everything else is set afterwards.
    writeable = "n" if desired.get("read only", "yes").lower() in ("yes", "true", "1") else "y"
    guest = "y" if desired.get("guest ok", "no").lower() in ("yes", "true", "1") else "n"
    steps.append(Step(["net", "conf", "addshare", name, path, f"writeable={writeable}", f"guest_ok={guest}"],
                      f"Create share [{name}]"))
    # Set every param explicitly rather than assume what addshare wrote.
    steps += share_plan(name, {"path": path}, desired)
    return Plan(f"Create SMB share [{name}]", steps + [RELOAD])


def delete_share(name: str, existing: set[str]) -> Plan:
    if name not in existing:
        raise v.Invalid(f"No share named [{name}].")
    return Plan(f"Delete SMB share [{name}] (files are kept)",
                [Step(["net", "conf", "delshare", name], f"Remove share [{name}] from the config"), RELOAD])


# ---- users -------------------------------------------------------------------

def parse_pdbedit(text: str) -> list[dict]:
    users, cur = [], None
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if key == "Unix username":
            cur = {"name": value, "full_name": "", "disabled": False, "flags": "", "password_last_set": ""}
            users.append(cur)
        elif cur is None:
            continue
        elif key == "Account Flags":
            cur["flags"] = value.strip("[] ")
            cur["disabled"] = "D" in cur["flags"]
        elif key == "Full Name":
            cur["full_name"] = value
        elif key == "Password last set":
            cur["password_last_set"] = value
    return users


def parse_group(text: str) -> list[dict]:
    groups = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 4 or not parts[2].isdigit():
            continue
        groups.append({"name": parts[0], "gid": int(parts[2]),
                       "members": [m for m in parts[3].split(",") if m]})
    return groups


def parse_passwd(text: str) -> dict[str, dict]:
    users = {}
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and parts[2].isdigit():
            users[parts[0]] = {"uid": int(parts[2]), "gid": int(parts[3]), "shell": parts[6]}
    return users


def manageable_groups(groups: list[dict]) -> list[dict]:
    """Regular groups an admin would assign people to (skips system and user-namespace ranges)."""
    return [g for g in groups if 1000 <= g["gid"] < 60000 or g["name"] == "users"]


def _pw_input(pw: str) -> str:
    return f"{pw}\n{pw}\n"


def add_user(name: str, pw: str, groups: list[str], unix_users: dict, valid_groups: set[str]) -> Plan:
    name = v.account(name, "username")
    pw = v.password(pw)
    steps = []
    for g in groups:
        if g not in valid_groups:
            raise v.Invalid(f"Unknown group '{g}'.")
    if name not in unix_users:
        argv = ["useradd", "--no-create-home", "--shell", "/sbin/nologin", "--user-group"]
        if groups:
            argv += ["--groups", ",".join(groups)]
        steps.append(Step(argv + ["--", name], f"Create Linux account '{name}' (no login, no home)"))
    else:
        for g in groups:
            steps.append(Step(["gpasswd", "-a", name, g], f"Add '{name}' to group '{g}'"))
    steps.append(Step(["smbpasswd", "-s", "-a", name], f"Create Samba account '{name}'", input=_pw_input(pw)))
    return Plan(f"Add Samba user '{name}'", steps)


def set_password(name: str, pw: str) -> Plan:
    return Plan(f"Change Samba password for '{name}'",
                [Step(["smbpasswd", "-s", name], "Set Samba password", input=_pw_input(v.password(pw)))])


def set_enabled(name: str, enabled: bool) -> Plan:
    flag, word = ("-e", "Enable") if enabled else ("-d", "Disable")
    return Plan(f"{word} Samba user '{name}'", [Step(["smbpasswd", flag, name], f"{word} '{name}'")])


def delete_user(name: str) -> Plan:
    return Plan(f"Remove Samba user '{name}'",
                [Step(["smbpasswd", "-x", name], f"Delete Samba account '{name}' (Linux account is kept)")])


def set_groups(name: str, wanted: list[str], groups: list[dict], primary: str = "") -> Plan:
    # The primary group comes from passwd, not group membership, so gpasswd can't change it; leave it alone.
    by_name = {g["name"]: g for g in manageable_groups(groups) if g["name"] != primary}
    for g in wanted:
        if g not in by_name:
            raise v.Invalid(f"Unknown group '{g}'.")
    steps = []
    for g in by_name.values():
        member = name in g["members"]
        if g["name"] in wanted and not member:
            steps.append(Step(["gpasswd", "-a", name, g["name"]], f"Add '{name}' to '{g['name']}'"))
        elif g["name"] not in wanted and member:
            steps.append(Step(["gpasswd", "-d", name, g["name"]], f"Remove '{name}' from '{g['name']}'"))
    if not steps:
        raise v.Invalid("Nothing changed.")
    return Plan(f"Change groups for '{name}'", steps)


def add_group(name: str, groups: list[dict]) -> Plan:
    name = v.account(name, "group name")
    if any(g["name"] == name for g in groups):
        raise v.Invalid(f"Group '{name}' already exists.")
    return Plan(f"Create group '{name}'", [Step(["groupadd", "--", name], f"Create group '{name}'")])
