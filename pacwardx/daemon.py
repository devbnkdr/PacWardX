"""Background scanner. Runs as a systemd --user service, talks to the UI over a unix socket.

Protocol: one JSON object per line, one request per connection.
  {"cmd": "status"}                       -> summary + running flag
  {"cmd": "results"}                      -> full state
  {"cmd": "scan", "categories": [...]}    -> starts a scan in the background
  {"cmd": "scan_files", "roots": [...], "clam": bool}
  {"cmd": "config"} / {"cmd": "set_config", "config": {...}}
  {"cmd": "history"}
"""
from __future__ import annotations

import asyncio
import html
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime

from . import config, engine
from .findings import CATEGORY_LABELS


class Daemon:
    def __init__(self):
        self.cfg = config.load()
        self.state = engine.load_state()
        self.running: str | None = None       # description of the scan in progress
        self._lock = threading.Lock()
        self._starting = threading.Lock()  # requests are handled on several threads
        self._loop: asyncio.AbstractEventLoop | None = None

    # -- scanning ------------------------------------------------------------
    def _scan_sync(self, cats, label: str, history: bool = True):
        with self._lock:
            self.running = label
            try:
                old = json.loads(json.dumps(self.state))
                self.state = engine.run_categories(cats, self.cfg, self.state)
                if history:
                    engine.append_history(self.state)
                    self.weekly_summary()  # here, under the scan lock, so only one thread saves the state
                self._notify_new(old, self.state)
            finally:
                self.running = None

    def _file_scan_sync(self, roots, clam):
        with self._lock:
            self.running = "file scan"
            try:
                old = json.loads(json.dumps(self.state))
                self.state = engine.run_file_scan(self.cfg, self.state, roots=roots, clam=clam)
                engine.append_history(self.state)
                self._notify_new(old, self.state)
            finally:
                self.running = None

    def _start(self, label: str, target, *args) -> bool:
        with self._starting:
            if self.running:
                return False
            self.running = label  # claimed now, so a second request can't start a duplicate
            threading.Thread(target=target, args=args, daemon=True).start()
            return True

    def start_scan(self, cats, label="scan", history: bool = True) -> bool:
        return self._start(label, self._scan_sync, cats, label, history)

    def accept_changes(self) -> dict:
        with self._lock:
            self.state = engine.accept_changes(self.cfg, self.state)
        return self.state

    def start_file_scan(self, roots=None, clam=None) -> bool:
        return self._start("file scan", self._file_scan_sync, roots, clam)

    def _notify_new(self, old, new):
        if not self.cfg.get("notify", True):
            return
        fresh = engine.new_serious(old, new)
        if not fresh:
            return
        worst = max(fresh, key=lambda f: f["severity"] == "high")
        title = f"PacWardX: {len(fresh)} new {'issue' if len(fresh) == 1 else 'issues'}"
        body = "\n".join(f"[{CATEGORY_LABELS.get(f['category'], f['category'])}] {f['title']}" for f in fresh[:4])
        self._send(title, body, "critical" if worst["severity"] == "high" else "normal")

    def _send(self, title: str, body: str, urgency: str = "normal") -> None:
        if not shutil.which("notify-send"):
            return
        # Notification servers render markup in the body; finding titles can contain file names.
        subprocess.Popen(["notify-send", "-a", "PacWardX", "-u", urgency, "-i", "security-medium", title,
                          html.escape(body, quote=False)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def weekly_summary(self, now: float | None = None) -> bool:
        """Send the weekly summary if it's due. Returns True when one was sent."""
        if not self.cfg.get("weekly_summary", True) or not self.state.get("last_run"):
            return False
        now = now or time.time()
        last = float(self.state.get("weekly_summary_sent", 0) or 0)
        if now - last < 7 * 24 * 3600:
            return False
        s = engine.summary(self.state)
        c = s["counts"]
        open_items = c["high"] + c["medium"] + c["low"]
        body = (f"Score {s['score']}/100. {c['high']} high, {c['medium']} medium, {c['low']} low."
                if open_items else f"Score {s['score']}/100. Nothing needs your attention.")
        self._send("PacWardX: your weekly summary", body)
        self.state["weekly_summary_sent"] = now
        engine.save_state(self.state)
        return True

    # -- scheduling ----------------------------------------------------------
    async def change_watcher(self):
        """Cheap, frequent pass over the Changes category so new keys/services/ports alert fast."""
        await asyncio.sleep(90)
        while True:
            if not self.running:
                self.start_scan(["changes"], "change watch", history=False)
            await asyncio.sleep(max(1, int(self.cfg.get("change_watch_minutes", 5))) * 60)

    async def scheduler(self):
        await asyncio.sleep(20)  # let the desktop settle after login
        while True:
            try:
                await self._scheduled_round()
            except Exception as e:  # never let one bad round stop future scans
                print(f"pacwardx: scheduled scan failed: {e!r}", file=sys.stderr, flush=True)
            await asyncio.sleep(max(5, int(self.cfg.get("interval_minutes", 60))) * 60)

    async def _scheduled_round(self):
        if not self.running:
            # Reload settings in place: scans and the ignore command share this dict.
            new = config.load()
            for k in [k for k in self.cfg if k not in new]:
                del self.cfg[k]
            self.cfg.update(new)
            self.start_scan(engine.QUICK, "scheduled scan")
        # daily-ish full file scan
        last = (self.state.get("file_scan") or {}).get("ts")
        due = True
        if last:
            try:
                age_h = (datetime.now() - datetime.fromisoformat(last)).total_seconds() / 3600
                due = age_h >= float(self.cfg.get("file_scan_every_hours", 24))
            except ValueError:
                pass
        if due:
            # wait for the quick scan to finish, then run the file scan
            for _ in range(600):
                if not self.running:
                    break
                await asyncio.sleep(1)
            self.start_file_scan()

    # -- socket --------------------------------------------------------------
    def handle(self, req: dict) -> dict:
        cmd = req.get("cmd")
        if cmd == "ping":
            return {"ok": True, "pid": os.getpid()}
        if cmd == "status":
            return {"ok": True, "running": self.running, **engine.summary(self.state)}
        if cmd == "results":
            return {"ok": True, "running": self.running, "state": self.state}
        if cmd == "scan":
            cats = req.get("categories") or list(engine.QUICK)
            started = self.start_scan(cats, "manual scan")
            return {"ok": True, "started": started, "running": self.running}
        if cmd == "scan_files":
            started = self.start_file_scan(req.get("roots"), req.get("clam"))
            return {"ok": True, "started": started, "running": self.running}
        if cmd == "accept_changes":
            if self.running:
                return {"ok": False, "error": f"{self.running} in progress, try again in a moment"}
            self.accept_changes()
            return {"ok": True}
        if cmd in ("ignore", "unignore"):
            fid, note, on = str(req.get("id", "")), str(req.get("note", "")), cmd == "ignore"
            if self._lock.acquire(blocking=False):
                try:
                    self.state = engine.set_ignored(self.cfg, self.state, fid, on, note)
                finally:
                    self._lock.release()
            else:
                # A scan is running and will save the state when it ends. Update the settings now (the scan
                # shares self.cfg, so it applies them) instead of waiting for a long scan to finish.
                engine.set_ignored(self.cfg, self.state, fid, on, note, persist=False)
            return {"ok": True, "ignored": self.cfg.get("ignored", {})}
        if cmd == "reset_data":
            if not self._lock.acquire(blocking=False):
                return {"ok": False, "error": f"{self.running or 'a scan'} in progress, try again in a moment"}
            try:
                self.state = engine.reset_data()
            finally:
                self._lock.release()
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

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=10)
            req = json.loads(line.decode() or "{}")
            resp = await asyncio.get_running_loop().run_in_executor(None, self.handle, req)
        except Exception as e:
            resp = {"ok": False, "error": repr(e)}
        try:
            writer.write((json.dumps(resp) + "\n").encode())
            await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def serve(self):
        config.ensure_dirs()
        path = config.SOCKET_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            path.unlink()
        server = await asyncio.start_unix_server(self._client, path=str(path))
        os.chmod(path, 0o600)
        print(f"pacwardx daemon listening on {path}", flush=True)
        asyncio.create_task(self.scheduler())
        asyncio.create_task(self.change_watcher())
        async with server:
            await server.serve_forever()


def main():
    d = Daemon()
    try:
        asyncio.run(d.serve())
    except KeyboardInterrupt:
        pass
    finally:
        try:
            config.SOCKET_PATH.unlink()
        except OSError:
            pass


if __name__ == "__main__":
    main()
