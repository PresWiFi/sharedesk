"""Runs commands on the storage server over SSH, and turns change plans into audited command runs."""
from __future__ import annotations

import asyncio
import shlex
from dataclasses import dataclass, field

import asyncssh


@dataclass
class Result:
    code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.code == 0


class HostError(RuntimeError):
    """The server couldn't be reached, or a read command failed."""


class SSHHost:
    def __init__(self, host: str, port: int, user: str, key_path: str,
                 known_hosts: str | None, timeout: float = 60.0):
        self.host, self.port, self.user = host, port, user
        self.key_path, self.known_hosts, self.timeout = key_path, known_hosts, timeout
        self._conn: asyncssh.SSHClientConnection | None = None
        self._lock = asyncio.Lock()

    async def _connection(self) -> asyncssh.SSHClientConnection:
        async with self._lock:
            if self._conn is None:
                self._conn = await asyncssh.connect(
                    self.host, port=self.port, username=self.user,
                    client_keys=[self.key_path], known_hosts=self.known_hosts,
                    connect_timeout=10, keepalive_interval=30,
                )
            return self._conn

    async def run(self, argv: list[str], input: str | None = None) -> Result:
        # Every command runs through sudo; the host's sudoers file decides what's allowed.
        cmd = "sudo -n -- " + shlex.join(argv)
        for attempt in (0, 1):
            try:
                conn = await self._connection()
                r = await asyncio.wait_for(conn.run(cmd, input=input, check=False), self.timeout)
                code = r.exit_status if r.exit_status is not None else 255
                return Result(code, str(r.stdout or ""), str(r.stderr or ""))
            except (asyncssh.Error, OSError, asyncio.TimeoutError) as e:
                self._conn = None
                if attempt:
                    raise HostError(f"SSH to {self.user}@{self.host} failed: {e}") from e
        raise AssertionError("unreachable")

    async def read(self, argv: list[str]) -> str:
        """Run a read-only command and return stdout, raising if it fails."""
        r = await self.run(argv)
        if not r.ok:
            raise HostError(f"{shlex.join(argv)} failed ({r.code}): {r.stderr.strip() or r.stdout.strip()}")
        return r.stdout


@dataclass
class Step:
    argv: list[str]
    desc: str = ""
    input: str | None = None
    # stdin is shown in previews only when it's file content, never for passwords.
    show_input: bool = False
    ok_codes: tuple[int, ...] = (0,)

    def preview(self) -> dict:
        d = {"desc": self.desc, "cmd": shlex.join(self.argv)}
        if self.input is not None:
            d["input"] = self.input if self.show_input else "(hidden)"
        return d


@dataclass
class Plan:
    title: str
    steps: list[Step]
    # Runs if any step fails, to put things back (e.g. restore an exports file).
    rollback: list[Step] = field(default_factory=list)
    diff: str | None = None

    def preview(self) -> dict:
        return {"title": self.title, "steps": [s.preview() for s in self.steps],
                "rollback": [s.preview() for s in self.rollback], "diff": self.diff}


def _trim(text: str, limit: int = 2000) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "\n…(truncated)"


async def execute(host: SSHHost, plan: Plan) -> dict:
    results, ok = [], True
    for step in plan.steps:
        r = await host.run(step.argv, step.input)
        out = r.stderr if step.show_input else (r.stdout + r.stderr)
        results.append({"cmd": shlex.join(step.argv), "code": r.code, "output": _trim(out)})
        if r.code not in step.ok_codes:
            ok = False
            break
    rolled_back = []
    if not ok:
        for step in plan.rollback:
            r = await host.run(step.argv, step.input)
            rolled_back.append({"cmd": shlex.join(step.argv), "code": r.code,
                                "output": _trim(r.stderr if step.show_input else r.stdout + r.stderr)})
    return {"title": plan.title, "ok": ok, "steps": results, "rolled_back": rolled_back}
