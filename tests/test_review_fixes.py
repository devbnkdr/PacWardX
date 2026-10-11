"""Regression tests for problems found in the pre-release security review."""
import os
import stat

from pacwardx import config
from pacwardx.checks import auth, common, network, secrets

SSHD = 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=500,fd=3))'
LAN = 'tcp LISTEN 0 128 192.168.1.20:8000 0.0.0.0:* users:(("devserver",pid=600,fd=3))'


def _listen(monkeypatch, ss_text, ufw):
    monkeypatch.setattr(network, "priv", lambda *a, **k: {"text": ss_text})
    return {f.title: f.severity for f in network._listeners({}, ufw)}


def test_ssh_allowed_from_anywhere_is_not_reported_as_blocked(monkeypatch):
    ufw = {"active": True, "default_in": "deny",
           "rules": [{"dir": "IN", "action": "ALLOW", "to": "22/tcp", "from": "Anywhere"}]}
    found = _listen(monkeypatch, SSHD, ufw)
    assert "SSH is blocked by the firewall's default deny" not in found
    assert found["SSH is open to every network (a ufw rule allows it from anywhere)"] == "low"
    ufw["rules"] = []
    assert "SSH is blocked by the firewall's default deny" in _listen(monkeypatch, SSHD, ufw)


def test_listener_on_a_lan_address_is_judged_by_the_firewall(monkeypatch):
    found = _listen(monkeypatch, LAN, {"active": False})
    assert found["devserver is reachable on 192.168.1.20:8000"] == "low"
    found = _listen(monkeypatch, LAN, {"active": True, "default_in": "deny", "rules": []})
    assert found["devserver bound to 192.168.1.20:8000"] == "info"


def test_redact_hides_secret_values():
    token = "ghp_" + "Z9y8" * 9
    text = secrets.redact(f"curl -H 'Authorization: Bearer {token}' https://x && mysql --password=hunter22")
    assert token not in text and "hunter22" not in text and "‹redacted›" in text


def test_sudo_report_redacts_and_only_hides_pacwardxs_exact_helper_calls():
    lines = [
        "t host sudo[1]:  me : USER=root ; COMMAND=/usr/local/lib/pacwardx/pacwardx-priv sockets",
        "t host sudo[2]:  me : USER=root ; COMMAND=/usr/bin/sh -c evil #/usr/local/lib/pacwardx/pacwardx-priv",
        "t host sudo[3]:  me : USER=root ; COMMAND=/usr/bin/mysql --password=hunter22",
    ]
    cmds = list(auth.analyse(lines)["sudo_cmds"])
    assert any(c.startswith("/usr/bin/sh -c evil") for c in cmds)       # look-alikes stay visible
    assert not any(c.endswith("pacwardx-priv sockets") for c in cmds)    # PacWardX's own call is hidden
    assert not any("hunter22" in c for c in cmds)


def test_quoted_tunnel_hostnames_are_unquoted(tmp_path, monkeypatch):
    cfg = tmp_path / "config.yml"
    cfg.write_text('ingress:\n  - hostname: "app.example.com"  # dashboard\n    service: \'http://localhost:3000\'\n'
                   "  - service: http_status:404\n")
    monkeypatch.setattr(common, "TUNNEL_CONFIGS", (str(cfg),))
    assert common.tunnel_routes() == [("app.example.com", "http://localhost:3000", str(cfg))]


def test_data_folders_are_private():
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    leaky = config.DATA_DIR / "state.json"
    leaky.write_text("{}")
    os.chmod(leaky, 0o644)
    config.ensure_dirs()
    assert stat.S_IMODE(os.stat(config.DATA_DIR).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(leaky).st_mode) == 0o600


def test_commands_run_untranslated(monkeypatch):
    monkeypatch.setenv("LANG", "de_DE.UTF-8")
    monkeypatch.setenv("LC_ALL", "de_DE.UTF-8")
    assert common.sh(["sh", "-c", "echo $LC_ALL"]).strip() == "C"


def test_old_baselines_with_root_cron_text_dont_raise_false_alarms(monkeypatch):
    from pacwardx.checks import changes
    line = "0 3 * * * /usr/local/bin/backup --token=abc123secret"
    h = changes._root_cron([line]).popitem()[0]
    old_baseline = {"root_cron": {h: line}}                      # what earlier versions stored
    current = {"root_cron": changes._root_cron([h])}             # helper now returns fingerprints
    saved = {}
    monkeypatch.setattr(changes, "snapshot", lambda cfg=None: current)
    monkeypatch.setattr(changes, "load_baseline", lambda: old_baseline)
    monkeypatch.setattr(changes, "save_baseline", lambda snap: saved.update(snap))
    found = changes.run({})
    assert [f.severity for f in found] == ["ok"]
    assert "abc123secret" not in repr(saved)                      # the stored text is gone too


def test_daemon_never_starts_two_scans_at_once(monkeypatch):
    import threading

    from pacwardx import daemon
    gate = threading.Event()
    monkeypatch.setattr(daemon.Daemon, "_scan_sync", lambda self, *a: gate.wait(5))
    d = daemon.Daemon()
    assert d.start_scan(["changes"]) is True
    assert d.start_scan(["changes"]) is False
    assert d.start_file_scan() is False
    gate.set()


def test_shared_report_leaves_out_machine_and_user(monkeypatch, tmp_path):
    import socket
    from pathlib import Path

    from pacwardx import report
    home = tmp_path / "jdoe"
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setattr(socket, "gethostname", lambda: "jdoe-laptop")
    text = report.scrub(f"Accepted publickey for jdoe on jdoe-laptop\n{home}/.ssh/id_ed25519\njdoesmith stays")
    assert text == "Accepted publickey for <user> on <hostname>\n~/.ssh/id_ed25519\njdoesmith stays"


def test_delete_results_and_history_keeps_settings():
    from pacwardx import engine
    config.ensure_dirs()
    for p in (config.STATE_PATH, config.HISTORY_PATH, config.BASELINE_PATH, config.CACHE_PATH, config.CONFIG_PATH):
        p.write_text("{}")
    state = engine.reset_data()
    assert state["last_run"] is None
    assert not any(p.exists() for p in (config.STATE_PATH, config.HISTORY_PATH, config.BASELINE_PATH, config.CACHE_PATH))
    assert config.CONFIG_PATH.exists()
