"""Talk to the daemon; fall back to running checks in-process when it isn't there."""
from __future__ import annotations

import json
import socket

from . import config, engine


class DaemonClient:
    def call(self, req: dict, timeout: float = 30) -> dict:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(str(config.SOCKET_PATH))
            s.sendall((json.dumps(req) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        finally:
            s.close()
        return json.loads(buf.decode() or "{}")

    def available(self) -> bool:
        try:
            return self.call({"cmd": "ping"}, timeout=2).get("ok", False)
        except (OSError, ValueError):
            return False


class LocalBackend:
    """Same interface, runs synchronously in the caller's thread."""

    def __init__(self):
        self.cfg = config.load()
        self.state = engine.load_state()

    def available(self) -> bool:
        return True

    def call(self, req: dict, timeout: float = 30) -> dict:
        cmd = req.get("cmd")
        if cmd == "ping":
            return {"ok": True, "local": True}
        if cmd == "status":
            return {"ok": True, "running": None, **engine.summary(self.state)}
        if cmd == "results":
            return {"ok": True, "running": None, "state": self.state}
        if cmd == "scan":
            self.state = engine.run_categories(req.get("categories") or list(engine.QUICK), self.cfg, self.state)
            engine.append_history(self.state)
            return {"ok": True, "started": True, "running": None}
        if cmd == "scan_files":
            self.state = engine.run_file_scan(self.cfg, self.state, roots=req.get("roots"), clam=req.get("clam"))
            engine.append_history(self.state)
            return {"ok": True, "started": True, "running": None}
        if cmd == "accept_changes":
            self.state = engine.accept_changes(self.cfg, self.state)
            return {"ok": True}
        if cmd in ("ignore", "unignore"):
            self.state = engine.set_ignored(self.cfg, self.state, str(req.get("id", "")),
                                            cmd == "ignore", str(req.get("note", "")))
            return {"ok": True, "ignored": self.cfg.get("ignored", {})}
        if cmd == "reset_data":
            self.state = engine.reset_data()
            return {"ok": True}
        if cmd == "config":
            return {"ok": True, "config": self.cfg}
        if cmd == "set_config":
            self.cfg.update(req.get("config", {}))
            config.save(self.cfg)
            return {"ok": True, "config": self.cfg}
        if cmd == "history":
            return {"ok": True, "history": engine.read_history()}
        return {"ok": False, "error": f"unknown command {cmd!r}"}


def pick_backend():
    d = DaemonClient()
    if d.available():
        return d, True
    return LocalBackend(), False
