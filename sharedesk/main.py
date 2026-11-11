"""ShareDesk web app: a small admin UI for Samba shares, NFS exports and folder permissions."""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import secrets
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from . import __version__, folders, nfs, samba
from . import validate as v
from .host import HostError, Plan, SSHHost, execute

log = logging.getLogger("sharedesk")
STATIC = Path(__file__).parent / "static"


class Settings:
    def __init__(self, env=os.environ):
        self.ssh_host = env.get("SHAREDESK_SSH_HOST", "")
        self.ssh_port = int(env.get("SHAREDESK_SSH_PORT", "22"))
        self.ssh_user = env.get("SHAREDESK_SSH_USER", "sharedesk")
        self.ssh_key = env.get("SHAREDESK_SSH_KEY", "/config/id_ed25519")
        self.known_hosts = env.get("SHAREDESK_KNOWN_HOSTS", "/config/known_hosts")
        self.insecure_hostkey = env.get("SHAREDESK_INSECURE_HOSTKEY", "") == "1"
        self.share_root = v.abs_path(env.get("SHAREDESK_SHARE_ROOT", "/mnt/shares"))
        self.default_group = env.get("SHAREDESK_DEFAULT_GROUP", "sambashare")
        self.password = env.get("SHAREDESK_ADMIN_PASSWORD", "")
        self.secret = env.get("SHAREDESK_SECRET") or secrets.token_hex(32)
        self.secure_cookie = env.get("SHAREDESK_SECURE_COOKIE", "") == "1"
        self.data_dir = Path(env.get("SHAREDESK_DATA_DIR", "/data"))
        protected = env.get("SHAREDESK_PROTECTED_USERS", "root")
        self.protected_users = {u.strip() for u in protected.split(",") if u.strip()} | {"root", self.ssh_user}


def create_app(settings: Settings | None = None, host=None) -> FastAPI:
    s = settings or Settings()
    if not s.password:
        raise SystemExit("Set SHAREDESK_ADMIN_PASSWORD.")
    if host is None:
        if not s.ssh_host:
            raise SystemExit("Set SHAREDESK_SSH_HOST.")
        known = None if s.insecure_hostkey else s.known_hosts
        host = SSHHost(s.ssh_host, s.ssh_port, s.ssh_user, s.ssh_key, known)

    app = FastAPI(title="ShareDesk", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SessionMiddleware, secret_key=s.secret, session_cookie="sharedesk",
                       max_age=12 * 3600, same_site="strict", https_only=s.secure_cookie)
    write_lock = asyncio.Lock()
    failed_logins: dict[str, list[float]] = {}
    s.data_dir.mkdir(parents=True, exist_ok=True)
    audit_file = s.data_dir / "audit.jsonl"

    @app.exception_handler(v.Invalid)
    async def _invalid(_req, exc):
        return JSONResponse({"error": str(exc)}, status_code=400)

    @app.exception_handler(HostError)
    async def _host(_req, exc):
        return JSONResponse({"error": str(exc)}, status_code=502)

    def require_login(request: Request):
        if not request.session.get("ok"):
            raise HTTPException(401, "Log in first.")

    def require_write(request: Request):
        require_login(request)
        # Cheap CSRF guard on top of SameSite=strict: browsers can't send this header cross-site without CORS.
        if request.headers.get("x-sharedesk") != "1":
            raise HTTPException(403, "Missing X-ShareDesk header.")

    def audit(request: Request, result: dict):
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                 "ip": request.client.host if request.client else "", **result}
        with audit_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    async def apply(request: Request, plan: Plan, body: dict):
        if body.get("preview"):
            return {"preview": plan.preview()}
        async with write_lock:
            result = await execute(host, plan)
        audit(request, result)
        if not result["ok"]:
            return JSONResponse({"error": "A command failed; see details.", "result": result}, status_code=409)
        return {"result": result}

    # ---- auth ----------------------------------------------------------------

    @app.post("/api/login")
    async def login(request: Request):
        ip = request.client.host if request.client else "?"
        recent = [t for t in failed_logins.get(ip, []) if time.time() - t < 300]
        if len(recent) >= 5:
            raise HTTPException(429, "Too many attempts. Wait 5 minutes.")
        body = await request.json()
        if not hmac.compare_digest(str(body.get("password", "")).encode(), s.password.encode()):
            failed_logins[ip] = recent + [time.time()]
            raise HTTPException(401, "Wrong password.")
        failed_logins.pop(ip, None)
        request.session["ok"] = True
        return {"ok": True}

    @app.post("/api/logout")
    async def logout(request: Request):
        request.session.clear()
        return {"ok": True}

    @app.get("/api/me")
    async def me(request: Request):
        return {"logged_in": bool(request.session.get("ok")), "version": __version__,
                "host": s.ssh_host, "share_root": s.share_root, "default_group": s.default_group}

    # ---- reads ---------------------------------------------------------------

    async def smb_conf() -> dict[str, dict[str, str]]:
        return samba.parse_conf(await host.read(["net", "conf", "list"]))

    async def exports() -> tuple[dict[str, str], list[dict]]:
        files = {nfs.MAIN: await host.read(["cat", nfs.MAIN])}
        listing = await host.read(["find", "/etc/exports.d", "-maxdepth", "1", "-type", "f", "-name", "*.exports"])
        for f in sorted(listing.split()):
            files[f] = await host.read(["cat", f])
        entries = [e for f, text in files.items() for e in nfs.parse(f, text)]
        return files, entries

    async def accounts():
        users = samba.parse_pdbedit(await host.read(["pdbedit", "-L", "-v"]))
        groups = samba.parse_group(await host.read(["getent", "group"]))
        unix = samba.parse_passwd(await host.read(["getent", "passwd"]))
        return users, groups, unix

    @app.get("/api/overview", dependencies=[Depends(require_login)])
    async def overview():
        conf, (_, entries), dirs = await smb_conf(), await exports(), await folders.list_folders(host, s.share_root)
        services = {}
        for unit in ("smb", "nmb", "nfs-server"):
            r = await host.run(["systemctl", "is-active", unit])
            services[unit] = r.stdout.strip() or "unknown"
        df = (await host.read(["df", "-B1", "--output=size,used,avail", s.share_root])).split()
        disk = dict(zip(("size", "used", "avail"), map(int, df[-3:]))) if len(df) >= 6 else None
        for d in dirs:
            d["smb"] = [{"name": n, **p} for n, p in conf.items() if n != "global" and p.get("path") == d["path"]]
            d["nfs"] = [e for e in entries if e["path"] == d["path"]]
        return {"services": services, "disk": disk, "folders": dirs}

    @app.get("/api/smb", dependencies=[Depends(require_login)])
    async def smb_list():
        conf = await smb_conf()
        smb_conf_file = samba.parse_conf(await host.read(["cat", "/etc/samba/smb.conf"]))
        return {"registry": samba.uses_registry(smb_conf_file.get("global", {})),
                "shares": [{"name": n, "params": p} for n, p in conf.items() if n != "global"]}

    @app.get("/api/users", dependencies=[Depends(require_login)])
    async def users_list():
        users, groups, unix = await accounts()
        manageable = samba.manageable_groups(groups)
        primary = {g["gid"]: g["name"] for g in groups}
        for u in users:
            info = unix.get(u["name"], {})
            u["uid"] = info.get("uid")
            u["primary_group"] = primary.get(info.get("gid"), "")
            u["groups"] = [g["name"] for g in manageable
                           if u["name"] in g["members"] or g["name"] == u["primary_group"]]
            u["protected"] = u["name"] in s.protected_users
        return {"users": users, "groups": manageable}

    @app.get("/api/nfs", dependencies=[Depends(require_login)])
    async def nfs_list():
        files, entries = await exports()
        return {"files": list(files), "exports": entries, "managed_file": nfs.MANAGED}

    @app.get("/api/folders", dependencies=[Depends(require_login)])
    async def folders_list():
        return {"folders": await folders.list_folders(host, s.share_root)}

    @app.get("/api/activity", dependencies=[Depends(require_login)])
    async def activity():
        if not audit_file.exists():
            return {"entries": []}
        lines = audit_file.read_text(encoding="utf-8").splitlines()[-200:]
        return {"entries": [json.loads(l) for l in reversed(lines) if l.strip()]}

    # ---- writes --------------------------------------------------------------

    def plan_path(body: dict) -> str:
        return str((body.get("params") or {}).get("path", ""))

    @app.post("/api/smb/create", dependencies=[Depends(require_write)])
    async def smb_create(request: Request):
        body = await request.json()
        conf = await smb_conf()
        plan = samba.create_share(body.get("name", ""), body.get("params", {}), s.share_root,
                                  set(conf), body.get("mkdir"))
        if not body.get("mkdir"):
            await folders.resolve(host, plan_path(body), s.share_root)
        return await apply(request, plan, body)

    @app.post("/api/smb/update", dependencies=[Depends(require_write)])
    async def smb_update(request: Request):
        body = await request.json()
        name = body.get("name", "")
        conf = await smb_conf()
        if name not in conf or name == "global":
            raise v.Invalid(f"No share named [{name}].")
        new_path = plan_path(body)
        if new_path and new_path != conf[name].get("path"):
            body["params"]["path"] = await folders.resolve(host, new_path, s.share_root)
        return await apply(request, samba.update_share(name, conf[name], body.get("params", {}), s.share_root), body)

    @app.post("/api/smb/delete", dependencies=[Depends(require_write)])
    async def smb_delete(request: Request):
        body = await request.json()
        conf = await smb_conf()
        return await apply(request, samba.delete_share(body.get("name", ""), set(conf) - {"global"}), body)

    def guard_user(name: str):
        if name in s.protected_users:
            raise v.Invalid(f"'{name}' is protected (SHAREDESK_PROTECTED_USERS).")

    async def known_user(name: str) -> None:
        users, _, _ = await accounts()
        if name not in {u["name"] for u in users}:
            raise v.Invalid(f"No Samba user '{name}'.")

    @app.post("/api/users/create", dependencies=[Depends(require_write)])
    async def user_create(request: Request):
        body = await request.json()
        users, groups, unix = await accounts()
        name = v.account(body.get("name", ""), "username")
        if name in {u["name"] for u in users}:
            raise v.Invalid(f"Samba user '{name}' already exists.")
        if name in unix and unix[name]["uid"] < 1000:
            raise v.Invalid(f"'{name}' is a system account.")
        valid = {g["name"] for g in samba.manageable_groups(groups)}
        plan = samba.add_user(name, body.get("password", ""), body.get("groups", []), unix, valid)
        return await apply(request, plan, body)

    @app.post("/api/users/password", dependencies=[Depends(require_write)])
    async def user_password(request: Request):
        body = await request.json()
        await known_user(body.get("name", ""))
        return await apply(request, samba.set_password(body["name"], body.get("password", "")), body)

    @app.post("/api/users/enabled", dependencies=[Depends(require_write)])
    async def user_enabled(request: Request):
        body = await request.json()
        await known_user(body.get("name", ""))
        if not body.get("enabled"):
            guard_user(body["name"])
        return await apply(request, samba.set_enabled(body["name"], bool(body.get("enabled"))), body)

    @app.post("/api/users/delete", dependencies=[Depends(require_write)])
    async def user_delete(request: Request):
        body = await request.json()
        await known_user(body.get("name", ""))
        guard_user(body["name"])
        return await apply(request, samba.delete_user(body["name"]), body)

    @app.post("/api/users/groups", dependencies=[Depends(require_write)])
    async def user_groups(request: Request):
        body = await request.json()
        _, groups, unix = await accounts()
        name = body.get("name", "")
        if name not in unix:
            raise v.Invalid(f"No Linux account '{name}'.")
        primary = next((g["name"] for g in groups if g["gid"] == unix[name]["gid"]), "")
        return await apply(request, samba.set_groups(name, body.get("groups", []), groups, primary), body)

    @app.post("/api/groups/create", dependencies=[Depends(require_write)])
    async def group_create(request: Request):
        body = await request.json()
        _, groups, _ = await accounts()
        return await apply(request, samba.add_group(body.get("name", ""), groups), body)

    @app.post("/api/nfs/create", dependencies=[Depends(require_write)])
    async def nfs_create(request: Request):
        body = await request.json()
        files, entries = await exports()
        path = await folders.resolve(host, body.get("path", ""), s.share_root)
        return await apply(request, nfs.add(files.get(nfs.MANAGED), path, body.get("clients", []),
                                            s.share_root, entries), body)

    def nfs_file(files: dict[str, str], body: dict) -> str:
        f = body.get("file", "")
        if f not in files:
            raise v.Invalid(f"Unknown exports file '{f}'.")
        return f

    @app.post("/api/nfs/update", dependencies=[Depends(require_write)])
    async def nfs_update(request: Request):
        body = await request.json()
        files, _ = await exports()
        f = nfs_file(files, body)
        return await apply(request, nfs.update(f, files[f], body.get("id", ""), body.get("path", ""),
                                               body.get("clients", [])), body)

    @app.post("/api/nfs/delete", dependencies=[Depends(require_write)])
    async def nfs_delete(request: Request):
        body = await request.json()
        files, _ = await exports()
        f = nfs_file(files, body)
        return await apply(request, nfs.delete(f, files[f], body.get("id", "")), body)

    @app.post("/api/folders/update", dependencies=[Depends(require_write)])
    async def folder_update(request: Request):
        body = await request.json()
        path = await folders.resolve(host, body.get("path", ""), s.share_root)
        if body.get("recursive") and path == s.share_root:
            raise v.Invalid("Recursive changes on the whole share root aren't allowed; do one folder at a time.")
        current = await folders.stat(host, path)
        plan = folders.change(path, current, body.get("owner", ""), body.get("group", ""), body.get("mode", ""),
                              bool(body.get("recursive")), body.get("file_mode"))
        return await apply(request, plan, body)

    # ---- UI ------------------------------------------------------------------

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-store"})

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "version": __version__}

    return app


def app_factory() -> FastAPI:
    logging.basicConfig(level=logging.INFO)
    return create_app()
