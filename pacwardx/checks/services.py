"""Checks for the services this machine runs: tunnels, containers, game servers."""
from __future__ import annotations

import glob
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .. import __version__
from ..findings import Finding
from .common import have, sh, tunnel_routes
from .secrets import redact

HOME = Path.home()


# ----------------------------------------------------------------------------- tunnels
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def probe(url: str, timeout: float = 10) -> tuple[int | None, str, str]:
    """(status, location header, short body) without following redirects."""
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": f"PacWardX/{__version__} (login check)"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.headers.get("Location", ""), r.read(600).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(600).decode("utf-8", "replace")
        except Exception:
            pass
        return e.code, e.headers.get("Location", "") if e.headers else "", body
    except Exception as e:  # DNS, TLS, timeout
        return None, "", repr(e)


def judge(host: str, status: int | None, location: str, body: str, cfg: dict) -> Finding:
    """Exposed for tests."""
    cat = "network"
    if host in cfg.get("tunnel_public_hosts", []):
        return Finding(cat, "info", f"{host} is public by design", f"HTTP {status}. Listed in tunnel_public_hosts.")
    if status is None:
        return Finding(cat, "info", f"{host}: login test couldn't reach it", redact(body[:300]))
    if status in (401, 403, 407):
        return Finding(cat, "ok", f"{host} refuses requests without credentials (HTTP {status})")
    if status in (301, 302, 303, 307, 308):
        if "cloudflareaccess.com" in location:
            return Finding(cat, "ok", f"{host} is behind Cloudflare Access")
        return Finding(cat, "info", f"{host} redirects anonymous visitors (HTTP {status})", f"→ {location}")
    if status in (502, 503, 504, 520, 521, 522, 523, 530):
        return Finding(cat, "info", f"{host}: backend not responding (HTTP {status})",
                       "Nothing to test while the service is down.")
    if 200 <= status < 300:
        return Finding(cat, "high", f"{host} answers the internet without a login (HTTP {status})",
                       "An anonymous request from the internet got a normal page back. If this is a control "
                       "panel or API, anyone who finds the hostname can use it. Add a token check in the app, "
                       "or put Cloudflare Access in front of it. If it's meant to be public, add it to "
                       "tunnel_public_hosts in ~/.config/pacwardx/config.json.\n\nFirst bytes:\n" + redact(body[:300]),
                       fix="Cloudflare dashboard → Zero Trust → Access → Applications → add " + host)
    return Finding(cat, "info", f"{host} returned HTTP {status} to an anonymous request", redact(body[:300]))


def tunnel_auth(cfg: dict) -> list[Finding]:
    out = []
    for host in sorted({host for host, _svc, _path in tunnel_routes()}):
        status, loc, body = probe(f"https://{host}/")
        out.append(judge(host, status, loc, body, cfg))
    return out


# ----------------------------------------------------------------------------- docker
SENSITIVE_MOUNTS = ("/", "/etc", "/root", "/home", "/boot", "/usr", "/var/lib/docker", "/proc", "/sys", "/dev")


def docker_hygiene(cfg: dict) -> list[Finding]:
    if not have("docker"):
        return []
    ids = sh(["docker", "ps", "-q"], timeout=20)
    if ids is None:
        return [Finding("system", "info", "Docker not reachable", "The daemon is down or you're not in the docker group.")]
    ids = ids.split()
    if not ids:
        return []
    raw = sh(["docker", "inspect", *ids], timeout=30)
    try:
        conts = json.loads(raw or "[]")
    except ValueError:
        return []
    img_ids = sorted({c.get("Image", "") for c in conts if c.get("Image")})
    created = {}
    if img_ids:
        try:
            for im in json.loads(sh(["docker", "image", "inspect", *img_ids], timeout=30) or "[]"):
                created[im.get("Id")] = im.get("Created", "")
        except ValueError:
            pass
    return evaluate_containers(conts, created, cfg)


def evaluate_containers(conts: list[dict], image_created: dict, cfg: dict) -> list[Finding]:
    """Exposed for tests."""
    cat = "system"
    ok_sock = [s.lower() for s in cfg.get("docker_socket_ok", [])]
    ok_host = [s.lower() for s in cfg.get("host_network_ok", [])]
    ok_old = [s.lower() for s in cfg.get("old_image_ok", [])]
    priv, sock_bad, sock_ok, hostns, mounts, old = [], [], [], [], [], []
    hostns_ok, old_ok = [], []
    now = datetime.now(timezone.utc)
    for c in conts:
        name = c.get("Name", "?").lstrip("/")
        hc = c.get("HostConfig", {}) or {}
        if hc.get("Privileged"):
            priv.append(name)
        for m in c.get("Mounts", []) or []:
            src = m.get("Source", "")
            if src in ("/var/run/docker.sock", "/run/docker.sock"):
                (sock_ok if any(k in name.lower() for k in ok_sock) else sock_bad).append(name)
            elif src in SENSITIVE_MOUNTS and m.get("RW", True):
                mounts.append(f"{name}: {src} (read-write)")
        if hc.get("NetworkMode") == "host" or hc.get("PidMode") == "host":
            line = f"{name}: network={hc.get('NetworkMode')} pid={hc.get('PidMode') or 'private'}"
            (hostns_ok if any(k in name.lower() for k in ok_host) else hostns).append(line)
        ts = image_created.get(c.get("Image", ""), "")
        if ts:
            try:
                d = datetime.fromisoformat(ts[:19]).replace(tzinfo=timezone.utc)
                age = (now - d).days
                if age > 180:
                    img = c.get('Config', {}).get('Image', '?')
                    (old_ok if any(k in img.lower() for k in ok_old) else old).append(f"{name}: {img} built {age} days ago")
            except ValueError:
                pass
    out = []
    if priv:
        out.append(Finding(cat, "high", f"Privileged containers: {', '.join(priv)}",
                           "A privileged container can take over the host. Drop --privileged unless it's truly needed.",
                           fix="Remove `privileged: true` from the compose file"))
    if sock_bad:
        out.append(Finding(cat, "medium", f"Containers with the Docker socket: {', '.join(sock_bad)}",
                           "Access to docker.sock is root on the host. Anything that compromises this container "
                           "owns the machine. Add the name to docker_socket_ok if it's a management tool you trust."))
    if sock_ok:
        out.append(Finding(cat, "info", f"Trusted containers with the Docker socket: {', '.join(sock_ok)}",
                           "Management tools that need it. Keep them updated and bound to localhost."))
    if hostns:
        out.append(Finding(cat, "medium", f"{len(hostns)} containers share the host network/process namespace",
                           "\n".join(hostns)))
    if hostns_ok:
        out.append(Finding(cat, "info", f"Accepted on the host network: {', '.join(l.split(':')[0] for l in hostns_ok)}",
                           "Listed in host_network_ok. The container can reach every service bound to localhost.\n\n"
                           + "\n".join(hostns_ok)))
    if mounts:
        out.append(Finding(cat, "medium", f"{len(mounts)} containers mount sensitive host folders read-write",
                           "\n".join(mounts)))
    if old:
        out.append(Finding(cat, "low", f"{len(old)} running containers use images older than 6 months",
                           "Old images carry old OpenSSL, glibc, etc. Pull and recreate them.\n\n" + "\n".join(old),
                           fix="docker compose pull && docker compose up -d   (in each project)"))
    if old_ok:
        out.append(Finding(cat, "info", f"Known-old images: {', '.join(l.split(':')[0] for l in old_ok)}",
                           "Listed in old_image_ok: no newer release exists upstream. Keep them bound to localhost.\n\n"
                           + "\n".join(old_ok)))
    if not out:
        out.append(Finding(cat, "ok", f"{len(conts)} running containers: no privileged, socket or host-namespace risks"))
    return out


# ----------------------------------------------------------------------------- minecraft
def _minecraft_dirs(cfg: dict) -> list[str]:
    dirs = list(cfg.get("minecraft_dirs", []))
    units = sh(["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"]) or ""
    for line in units.splitlines():
        u = line.split()[0] if line.split() else ""
        if "minecraft" in u.lower() or "mc-" in u.lower():
            wd = (sh(["systemctl", "show", "-p", "WorkingDirectory", "--value", u]) or "").strip()
            if wd and wd not in dirs:
                dirs.append(wd)
    return [d for d in dirs if os.path.isfile(os.path.join(d, "server.properties"))]


def parse_properties(text: str) -> dict:
    props = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        props[k.strip()] = v.strip()
    return props


def evaluate_minecraft(d: str, props: dict, extras: dict) -> list[Finding]:
    """Exposed for tests. extras: {'ops': [...], 'whitelist': int, 'jar_age_days': int|None}"""
    cat = "network"
    name = os.path.basename(d.rstrip("/")) or d
    out = []
    if props.get("online-mode", "true") == "false":
        out.append(Finding(cat, "high", f"Minecraft ({name}): online-mode is off",
                           "Players aren't verified with Mojang, so anyone can join as any name — including your ops.",
                           fix="online-mode=true in server.properties"))
    if props.get("white-list", "false") != "true":
        out.append(Finding(cat, "medium", f"Minecraft ({name}): whitelist is off",
                           "Anyone who finds your IP and port can join.", fix="white-list=true, then /whitelist add <name>"))
    if props.get("enable-rcon", "false") == "true":
        ip = props.get("rcon.ip", "")
        if ip not in ("127.0.0.1", "localhost", "::1"):
            out.append(Finding(cat, "high", f"Minecraft ({name}): RCON listens on all interfaces",
                               "RCON is full console access. Bind it to localhost.", fix="rcon.ip=127.0.0.1"))
        if len(props.get("rcon.password", "")) < 16:
            out.append(Finding(cat, "medium", f"Minecraft ({name}): RCON password is short",
                               "Use 24+ random characters."))
    if props.get("enable-query", "false") == "true":
        out.append(Finding(cat, "low", f"Minecraft ({name}): query protocol enabled",
                           "Publishes player list and plugins over UDP. Rarely needed.", fix="enable-query=false"))
    age = extras.get("jar_age_days")
    if age is not None and age > 120:
        out.append(Finding(cat, "low", f"Minecraft ({name}): server jar is {age} days old",
                           "Game servers get remote-exploit fixes (e.g. Log4Shell). Update the server and mods."))
    ops = extras.get("ops", [])
    wl = extras.get("whitelist")
    detail = f"Operators: {', '.join(ops) or 'none'}\nWhitelisted players: {wl if wl is not None else '?'}\n{d}"
    if not out:
        out.append(Finding(cat, "ok", f"Minecraft ({name}): whitelist on, online-mode on, RCON local", detail))
    else:
        out.append(Finding(cat, "info", f"Minecraft ({name}): who has access", detail))
    return out


def minecraft(cfg: dict) -> list[Finding]:
    out = []
    for d in _minecraft_dirs(cfg):
        try:
            props = parse_properties(Path(d, "server.properties").read_text())
        except OSError:
            continue
        extras: dict = {}
        try:
            extras["ops"] = [o.get("name", "?") for o in json.loads(Path(d, "ops.json").read_text())]
        except (OSError, ValueError):
            extras["ops"] = []
        try:
            extras["whitelist"] = len(json.loads(Path(d, "whitelist.json").read_text()))
        except (OSError, ValueError):
            extras["whitelist"] = None
        jars = glob.glob(os.path.join(d, "*.jar"))
        extras["jar_age_days"] = int((time.time() - max(os.path.getmtime(j) for j in jars)) / 86400) if jars else None
        out.extend(evaluate_minecraft(d, props, extras))
    return out
