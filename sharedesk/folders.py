"""Owner, group and mode of the folders under the share root."""
from __future__ import annotations

from . import validate as v
from .host import HostError, Plan, SSHHost, Step

FIND_FORMAT = "%p\t%u\t%g\t%m\t%M\t%Z\n"


def parse_find(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        path, user, group, octal, symbolic, context = parts[:6]
        out.append({"path": path, "owner": user, "group": group, "mode": octal.zfill(4),
                    "symbolic": symbolic, "selinux": "" if context == "?" else context})
    return sorted(out, key=lambda f: f["path"].lower())


async def list_folders(host: SSHHost, root: str) -> list[dict]:
    text = await host.read(["find", root, "-mindepth", "0", "-maxdepth", "1", "-type", "d",
                            "-not", "-name", "lost+found", "-printf", FIND_FORMAT])
    return parse_find(text)


async def resolve(host: SSHHost, path: str, root: str) -> str:
    """Resolve symlinks on the host so a link can't point a change outside the share root."""
    path = v.under_root(path, root)
    r = await host.run(["realpath", "-e", "--", path])
    if not r.ok:
        raise v.Invalid(f"{path} doesn't exist on the server.")
    return v.under_root(r.stdout.strip(), root)


async def stat(host: SSHHost, path: str) -> dict:
    text = await host.read(["find", path, "-maxdepth", "0", "-printf", FIND_FORMAT])
    found = parse_find(text)
    if not found:
        raise HostError(f"Couldn't stat {path}.")
    return found[0]


def change(path: str, current: dict, owner: str, group: str, mode: str,
           recursive: bool, file_mode: str | None) -> Plan:
    owner = v.owner(owner, "owner")
    group = v.owner(group, "group")
    mode = v.mode(mode)
    steps = []
    if recursive or (owner, group) != (current["owner"], current["group"]):
        argv = ["chown"] + (["-R"] if recursive else []) + [f"{owner}:{group}", "--", path]
        steps.append(Step(argv, f"Set owner to {owner}:{group}" + (" on everything inside" if recursive else "")))
    # The extra leading 0 makes GNU chmod clear setgid/sticky on directories when the new mode drops them.
    if recursive:
        file_mode = v.mode(file_mode or "")
        steps += [
            Step(["find", path, "-type", "d", "-exec", "chmod", "0" + mode, "{}", "+"], f"Set folders to {mode}"),
            Step(["find", path, "-type", "f", "-exec", "chmod", "0" + file_mode, "{}", "+"], f"Set files to {file_mode}"),
        ]
    elif mode != current["mode"]:
        steps.append(Step(["chmod", "0" + mode, "--", path], f"Set mode {mode}"))
    if not steps:
        raise v.Invalid("Nothing changed.")
    return Plan(f"Change permissions on {path}" + (" (recursive)" if recursive else ""), steps)
