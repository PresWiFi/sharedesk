import shlex

import pytest
from fastapi.testclient import TestClient

from sharedesk import folders, nfs, samba
from sharedesk import validate as v
from sharedesk.host import Result
from sharedesk.main import Settings, create_app

NET_CONF = """[global]
\tinclude = registry

[Files]
\tpath = /mnt/shares/Files
\tread only = no
\tvalid users = @sambashare
\tforce group = sambashare
"""

EXPORTS = """#/mnt/shares/Files 192.168.1.0/24(rw)
/mnt/shares/Proxmox-nfs    192.168.1.0/24(rw,sync,no_subtree_check,no_root_squash) 192.168.40.0/24(rw,sync)

/mnt/shares/media          192.168.1.0/24(rw,sync,all_squash,anonuid=1000,anongid=1000)
"""

LAB = "/mnt/shares/lab          192.168.1.69(rw,sync,no_subtree_check,root_squash)\n"

PDBEDIT = """---------------
Unix username:        bob
Account Flags:        [U          ]
Full Name:            bob
Password last set:    Mon, 10 Aug 2026 16:18:10 MDT
---------------
Unix username:        alice
Account Flags:        [DU         ]
Full Name:            Alice
"""

GROUP = "root:x:0:\nbob:x:1000:\nsambashare:x:1001:bob\nlabapps:x:101000:\n"
PASSWD = "root:x:0:0::/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\nalice:x:1002:1002::/:/sbin/nologin\n"
FIND = ("/mnt/shares\troot\tsambashare\t2775\tdrwxrwsr-x\t?\n"
        "/mnt/shares/Files\tbob\tbob\t777\tdrwxrwxrwx\tsystem_u:object_r:unlabeled_t:s0\n")


class FakeHost:
    def __init__(self):
        self.calls = []

    async def run(self, argv, input=None):
        self.calls.append((argv, input))
        cmd = shlex.join(argv)
        table = {
            "net conf list": NET_CONF, "cat /etc/exports": EXPORTS,
            "cat /etc/samba/smb.conf": "[global]\n\tworkgroup = WG\n\tinclude = registry\n",
            "cat /etc/exports.d/lab.exports": LAB, "pdbedit -L -v": PDBEDIT,
            "getent group": GROUP, "getent passwd": PASSWD,
        }
        if cmd in table:
            return Result(0, table[cmd], "")
        if cmd.startswith("find /etc/exports.d"):
            return Result(0, "/etc/exports.d/lab.exports\n", "")
        if cmd.startswith("find /mnt/shares"):
            return Result(0, FIND, "")
        if cmd.startswith("realpath -e -- "):
            p = argv[-1]
            return Result(0, p + "\n", "") if p.startswith("/mnt/shares") and "missing" not in p else Result(1, "", "nope")
        if cmd.startswith("systemctl is-active"):
            return Result(3 if argv[-1] == "nmb" else 0, "inactive\n" if argv[-1] == "nmb" else "active\n", "")
        if cmd.startswith("df "):
            return Result(0, "1B-blocks Used Avail\n100 60 40\n", "")
        if cmd == "exportfs -ra" and getattr(self, "exportfs_fails", False) and not any(
                c[0][:2] == ["cp", "-a"] and c[0][-1] == "/etc/exports" for c in self.calls[:-1]):
            return Result(1, "", "exportfs: bad option")
        return Result(0, "", "")

    async def read(self, argv):
        r = await self.run(argv)
        assert r.ok, argv
        return r.stdout

    def writes(self):
        reads = ("net conf list", "cat ", "pdbedit -L", "getent ", "find ", "realpath ", "systemctl ", "df ")
        return [shlex.join(a) for a, _ in self.calls if not shlex.join(a).startswith(reads) or "-exec" in a]


@pytest.fixture
def env(tmp_path):
    s = Settings({"SHAREDESK_ADMIN_PASSWORD": "hunter22", "SHAREDESK_SSH_HOST": "storage",
                  "SHAREDESK_DATA_DIR": str(tmp_path), "SHAREDESK_PROTECTED_USERS": "bob"})
    host = FakeHost()
    client = TestClient(create_app(s, host))
    client.headers["X-ShareDesk"] = "1"
    return client, host


def login(client):
    assert client.post("/api/login", json={"password": "hunter22"}).status_code == 200


def test_requires_login(env):
    client, _ = env
    assert client.get("/api/smb").status_code == 401
    assert client.post("/api/login", json={"password": "nope"}).status_code == 401
    login(client)
    assert client.get("/api/smb").status_code == 200


def test_write_needs_csrf_header(env):
    client, _ = env
    login(client)
    del client.headers["X-ShareDesk"]
    assert client.post("/api/smb/delete", json={"name": "Files"}).status_code == 403


def test_overview_joins_everything(env):
    client, _ = env
    login(client)
    d = client.get("/api/overview").json()
    assert d["services"] == {"smb": "active", "nmb": "inactive", "nfs-server": "active"}
    assert d["disk"] == {"size": 100, "used": 60, "avail": 40}
    files = next(f for f in d["folders"] if f["path"] == "/mnt/shares/Files")
    assert files["smb"][0]["name"] == "Files" and files["mode"] == "0777"
    assert files["selinux"].startswith("system_u")


def test_smb_list_detects_registry(env):
    client, _ = env
    login(client)
    d = client.get("/api/smb").json()
    assert d["registry"] and [s["name"] for s in d["shares"]] == ["Files"]


def test_preview_runs_nothing(env):
    client, host = env
    login(client)
    r = client.post("/api/smb/update", json={"name": "Files", "preview": True, "params": {
        "path": "/mnt/shares/Files", "read only": "yes", "valid users": "@sambashare alice"}}).json()
    cmds = [s["cmd"] for s in r["preview"]["steps"]]
    assert "net conf delparm Files 'force group'" in cmds
    assert "net conf setparm Files 'read only' yes" in cmds
    assert "net conf setparm Files 'valid users' '@sambashare alice'" in cmds
    assert host.writes() == []


def test_apply_runs_and_audits(env):
    client, host = env
    login(client)
    r = client.post("/api/smb/delete", json={"name": "Files"})
    assert r.status_code == 200
    assert host.writes() == ["net conf delshare Files", "smbcontrol smbd reload-config"]
    assert client.get("/api/activity").json()["entries"][0]["title"].startswith("Delete SMB share [Files]")


def test_create_share_rejects_outside_root(env):
    client, _ = env
    login(client)
    r = client.post("/api/smb/create", json={"name": "Etc", "params": {"path": "/etc"}, "mkdir": None, "preview": True})
    assert r.status_code == 400 and "outside" in r.json()["error"]
    r = client.post("/api/smb/create", json={"name": "x", "params": {"path": "/mnt/shares/../etc"}, "preview": True})
    assert r.status_code == 400


def test_create_share_with_mkdir():
    plan = samba.create_share("Photos", {"path": "/mnt/shares/Photos", "read only": "no", "valid users": "@sambashare"},
                              "/mnt/shares", {"global", "Files"}, {"owner": "root", "group": "sambashare", "mode": "2775"})
    cmds = [shlex.join(s.argv) for s in plan.steps]
    assert cmds[:3] == ["mkdir -p -- /mnt/shares/Photos", "chown root:sambashare -- /mnt/shares/Photos",
                        "chmod 02775 -- /mnt/shares/Photos"]
    assert "net conf addshare Photos /mnt/shares/Photos writeable=y guest_ok=n" in cmds
    assert cmds[-1] == "smbcontrol smbd reload-config"


def test_users_listing_and_protection(env):
    client, host = env
    login(client)
    d = client.get("/api/users").json()
    bob = next(u for u in d["users"] if u["name"] == "bob")
    alice = next(u for u in d["users"] if u["name"] == "alice")
    assert bob["groups"] == ["bob", "sambashare"] and bob["protected"]
    assert alice["disabled"] and not alice["protected"]
    assert [g["name"] for g in d["groups"]] == ["bob", "sambashare"]  # skips root and subuid ranges
    assert client.post("/api/users/delete", json={"name": "bob"}).status_code == 400
    assert client.post("/api/users/enabled", json={"name": "bob", "enabled": False}).status_code == 400


def test_password_never_in_preview_or_audit(env, tmp_path):
    client, host = env
    login(client)
    r = client.post("/api/users/password", json={"name": "alice", "password": "s3cret-pass", "preview": True}).json()
    assert "s3cret-pass" not in str(r)
    client.post("/api/users/password", json={"name": "alice", "password": "s3cret-pass"})
    assert host.calls[-1] == (["smbpasswd", "-s", "alice"], "s3cret-pass\ns3cret-pass\n")
    assert "s3cret-pass" not in (tmp_path / "audit.jsonl").read_text()


def test_add_user_creates_unix_account():
    plan = samba.add_user("carol", "longpassword", ["sambashare"], {}, {"sambashare"})
    assert shlex.join(plan.steps[0].argv) == ("useradd --no-create-home --shell /sbin/nologin --user-group "
                                              "--groups sambashare -- carol")
    assert plan.steps[1].argv == ["smbpasswd", "-s", "-a", "carol"]


def test_set_groups_diff():
    groups = samba.parse_group(GROUP)
    plan = samba.set_groups("bob", [], groups, primary="bob")
    assert [shlex.join(s.argv) for s in plan.steps] == ["gpasswd -d bob sambashare"]
    plan = samba.set_groups("alice", ["sambashare"], groups, primary="alice")
    assert [shlex.join(s.argv) for s in plan.steps] == ["gpasswd -a alice sambashare"]
    with pytest.raises(v.Invalid):
        samba.set_groups("bob", ["labapps"], groups)


def test_nfs_parse():
    entries = nfs.parse("/etc/exports", EXPORTS)
    assert [e["path"] for e in entries] == ["/mnt/shares/Proxmox-nfs", "/mnt/shares/media"]
    assert entries[0]["clients"][0] == {"host": "192.168.1.0/24", "options": "rw,sync,no_subtree_check,no_root_squash"}
    assert entries[1]["line"] == 3
    cont = nfs.parse("f", "/a \\\n  host1(ro) \\\n  host2\n/b h(rw)\n")
    assert cont[0]["clients"] == [{"host": "host1", "options": "ro"}, {"host": "host2", "options": ""}]
    assert cont[0]["span"] == 3 and cont[1]["line"] == 3


def test_nfs_update_keeps_other_lines(env):
    client, host = env
    login(client)
    e = client.get("/api/nfs").json()["exports"][0]
    r = client.post("/api/nfs/update", json={"file": e["file"], "id": e["id"], "path": e["path"],
                                              "clients": [{"host": "192.168.1.0/24", "options": "rw,sync,root_squash"}]})
    assert r.status_code == 200
    written = next(i for a, i in host.calls if a == ["tee", "/etc/exports"])
    assert written.splitlines()[0] == "#/mnt/shares/Files 192.168.1.0/24(rw)"
    assert "192.168.1.0/24(rw,sync,root_squash)" in written.splitlines()[1]
    assert "192.168.40.0" not in written and "/mnt/shares/media" in written
    assert host.writes() == ["cp -a -- /etc/exports /etc/exports.sharedesk-bak", "tee /etc/exports", "exportfs -ra"]


def test_nfs_stale_id_rejected(env):
    client, _ = env
    login(client)
    r = client.post("/api/nfs/delete", json={"file": "/etc/exports", "id": "deadbeef"})
    assert r.status_code == 400 and "changed" in r.json()["error"]


def test_nfs_rolls_back_when_exportfs_fails(env):
    client, host = env
    host.exportfs_fails = True
    login(client)
    e = client.get("/api/nfs").json()["exports"][1]
    r = client.post("/api/nfs/delete", json={"file": e["file"], "id": e["id"]})
    assert r.status_code == 409
    res = r.json()["result"]
    assert not res["ok"] and [s["cmd"] for s in res["rolled_back"]] == [
        "cp -a -- /etc/exports.sharedesk-bak /etc/exports", "exportfs -ra"]


def test_nfs_create_goes_to_managed_file(env):
    client, host = env
    login(client)
    r = client.post("/api/nfs/create", json={"path": "/mnt/shares/media", "preview": True,
                                              "clients": [{"host": "192.168.1.50", "options": "ro"}]})
    assert r.status_code == 400 and "already exported" in r.json()["error"]
    r = client.post("/api/nfs/create", json={"path": "/mnt/shares/new", "preview": True,
                                              "clients": [{"host": "192.168.1.50", "options": "ro,sync"}]}).json()
    assert r["preview"]["steps"][0]["cmd"] == "tee /etc/exports.d/sharedesk.exports"
    assert "+/mnt/shares/new" in r["preview"]["diff"]


def test_nfs_rejects_bad_client():
    with pytest.raises(v.Invalid):
        nfs.clean_clients([{"host": "10.0.0.1 evil", "options": "rw"}])
    with pytest.raises(v.Invalid):
        nfs.clean_clients([{"host": "10.0.0.1", "options": "rw)(x"}])


def test_folder_change_recursive():
    current = {"owner": "bob", "group": "bob", "mode": "0777"}
    plan = folders.change("/mnt/shares/Files", current, "bob", "sambashare", "2775", True, "664")
    assert [shlex.join(s.argv) for s in plan.steps] == [
        "chown -R bob:sambashare -- /mnt/shares/Files",
        "find /mnt/shares/Files -type d -exec chmod 02775 '{}' +",
        "find /mnt/shares/Files -type f -exec chmod 00664 '{}' +",
    ]
    plan = folders.change("/mnt/shares/Files", current, "bob", "bob", "775", False, None)
    assert [shlex.join(s.argv) for s in plan.steps] == ["chmod 00775 -- /mnt/shares/Files"]
    with pytest.raises(v.Invalid):
        folders.change("/mnt/shares/Files", current, "bob", "bob", "0777", False, None)


def test_folder_endpoint_guards(env):
    client, _ = env
    login(client)
    r = client.post("/api/folders/update", json={"path": "/mnt/shares", "owner": "root", "group": "root",
                                                 "mode": "755", "recursive": True, "file_mode": "644"})
    assert r.status_code == 400
    r = client.post("/api/folders/update", json={"path": "/mnt/shares/missing", "owner": "root", "group": "root", "mode": "755"})
    assert r.status_code == 400


def test_validators():
    assert v.mode("775") == "0775"
    for bad in ("9", "77777", "rwx"):
        with pytest.raises(v.Invalid):
            v.mode(bad)
    with pytest.raises(v.Invalid):
        v.param_value("a\nb")
    with pytest.raises(v.Invalid):
        v.share_name("global")
    with pytest.raises(v.Invalid):
        v.account("Bob")
