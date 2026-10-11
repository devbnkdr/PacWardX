"""Render the README screenshots offscreen from made-up demo data.

    QT_QPA_PLATFORM=offscreen python scripts/screenshots.py light
    QT_QPA_PLATFORM=offscreen python scripts/screenshots.py dark
"""
import sys, os, time
from datetime import datetime, timedelta
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication
import pacwardx.ui.app as A
from pacwardx.ui import style

now = datetime.now()
ts = lambda m: (now - timedelta(minutes=m)).isoformat(timespec="seconds")
F = lambda c, s, t, d="", fx="": {"category": c, "severity": s, "title": t, "detail": d, "fix": fx, "id": t}
state = {"last_run": ts(3), "file_scan": {"ts": ts(300), "files": 184213, "seconds": 41.2},
 "categories": {
  "packages": {"ts": ts(3), "seconds": 4.1, "findings": [
     F("packages","medium","3 security-relevant updates pending","firefox 131.0 -> 131.0.2\nopenssl 3.3.2 -> 3.3.3\nlinux 6.11.1 -> 6.11.3","sudo pacman -Syu"),
     F("packages","low","12 orphaned packages","Packages installed as dependencies that nothing needs anymore.","sudo pacman -Rns $(pacman -Qtdq)"),
     F("packages","info","Last full upgrade 2 days ago"), F("packages","ok","No arch-audit CVEs with a fix available")]},
  "network": {"ts": ts(3), "seconds": 2.3, "findings": [
     F("network","high","Port 8080 is reachable from the LAN and not allowed by the firewall",
       "Process: python3 (pid 41822)\nListening on 0.0.0.0:8080\nufw: no rule matches this port, but default incoming policy is 'allow'.",
       "sudo ufw default deny incoming && sudo ufw enable"),
     F("network","ok","Firewall (ufw) is active"), F("network","info","LLMNR is disabled")]},
  "system": {"ts": ts(3), "seconds": 3.0, "findings": [
     F("system","low","kernel.kptr_restrict is 0","Kernel pointers are visible to unprivileged users.","echo 'kernel.kptr_restrict = 2' | sudo tee /etc/sysctl.d/90-kptr.conf"),
     F("system","ok","sshd: root login and password auth disabled"), F("system","ok","No NOPASSWD sudo rules")]},
  "files": {"ts": ts(300), "seconds": 41.2, "findings": [F("files","ok","No executables in temp directories"), F("files","info","gitleaks: 14 repositories clean")]},
  "changes": {"ts": ts(1), "seconds": 0.4, "findings": [F("changes","medium","New user service enabled: syncthing.service","~/.config/systemd/user/default.target.wants/syncthing.service","systemctl --user disable --now syncthing.service")]},
  "opsec": {"ts": ts(3), "seconds": 1.9, "findings": [F("opsec","ok","Disk encryption: LUKS on root"), F("opsec","ok","Secure Boot enabled"), F("opsec","info","Tailscale: 3 peers, all yours")]},
 }}
POOL = [["u1", "medium", "packages", "3 security-relevant updates pending"],
        ["o1", "low", "packages", "12 orphaned packages"],
        ["p1", "high", "network", "Port 8080 is reachable from the LAN and not allowed by the firewall"],
        ["k1", "low", "system", "kernel.kptr_restrict is 0"],
        ["s1", "medium", "changes", "New user service enabled: syncthing.service"],
        ["b1", "low", "opsec", "Bluetooth is discoverable"]]
def hrow(k):
    open_ = [f for i, f in enumerate(POOL) if (k + i) % 3]
    counts = {s: sum(f[1] == s for f in open_) for s in ("high", "medium", "low")}
    worst = next((s for s in ("high", "medium", "low") if counts[s]), "ok")
    return {"ts": ts(60*k), "score": 100 - 12*counts["high"] - 6*counts["medium"] - 2*counts["low"], "worst": worst,
            "counts": counts, "findings": open_}
hist = [hrow(k) for k in range(14, 0, -1)]
cfg = {"interval_minutes": 60, "file_scan_every_hours": 24, "recent_days": 7, "notify": True, "clamav": False,
       "file_scan_roots": ["~"], "file_scan_exclude": [".cache", "node_modules", ".venv", ".local/share/Steam"], "allowed_listeners": ["syncthing"]}

class Fake:
    def call(self, req, timeout=30):
        return {"results": {"ok": True, "running": None, "state": state}, "history": {"ok": True, "history": hist},
                "config": {"ok": True, "config": cfg}}.get(req["cmd"], {"ok": True})
A.pick_backend = lambda: (Fake(), True)
# A typical setup for the Welcome page: everything installed except the optional ClamAV.
A.shutil.which = lambda cmd: None if cmd == "clamscan" else f"/usr/bin/{cmd}"
import pacwardx.checks.common as common
common.priv_available = lambda: True

mode = sys.argv[1]
if mode == "dark":
    style.is_dark = lambda: True
    import pacwardx.ui.widgets as W; W.style.is_dark = style.is_dark
app = QApplication(sys.argv)
style.apply(app)
win = A.MainWindow(False)
out = os.path.join(ROOT, "docs")
def go():
    win.state = state
    from pacwardx.engine import summary
    win.summary = summary(state); win._render(None)
    pages = [("overview", None)] if mode == "dark" else [("overview", None), ("network", 0), ("settings", None),
                                                          ("history", None), ("welcome", None),
                                                          ("help", None)]
    for key, sel in pages:
        win.nav.setCurrentItem(win.nav_items[key])
        if sel is not None:
            p = win.cat_pages[key]; p.tree.setCurrentItem(p.tree.topLevelItem(sel))
        for _ in range(30):
            app.processEvents(); time.sleep(0.02)
        win.grab().save(f"{out}/{key}-{mode}.png")
    app.quit()
QTimer.singleShot(400, go)
app.exec()
