"""Text for the Welcome and Help pages. Kept here so the app and its "?" buttons say the same thing."""
from __future__ import annotations

import re

ABOUT = (
    "PacWardX is a monitor for your Arch Linux or CachyOS computer. It reads your system, tells you in plain "
    "language what needs attention, and alerts you when something changes. It suggests fixes, but it never "
    "applies them, and it never sends your data anywhere."
)

DOES = [
    "Checks packages, network exposure, system settings, files and privacy settings",
    "Watches sensitive places (SSH keys, users, sudo rules, services, cron jobs, ports) and alerts on changes",
    "Explains each finding and suggests a fix you can copy",
    "Scans in the background and sends desktop alerts for new medium and high findings",
]

DOESNT = [
    "It doesn't protect you: no blocking, quarantining or undoing changes",
    "It never changes your system: every fix is yours to review and run",
    "It isn't real-time: scans run hourly, and every 5 minutes for changes",
    "It can't prove a machine is clean if someone already has root",
]

SEVERITIES = [
    ("high", "High", "Fix soon. Something is exposed, misconfigured or changed in a way attackers use."),
    ("medium", "Medium", "Worth fixing. A real weakness, but less urgent."),
    ("low", "Low", "Minor. Tidy up when convenient."),
    ("info", "Info", "For your awareness. Nothing to fix."),
    ("ok", "OK", "Checked and fine."),
]

CATEGORY_HELP = {
    "packages": [
        "Pending system and AUR updates, with security-relevant ones flagged",
        "Known vulnerabilities with a fix available (arch-audit)",
        "Time since the last full upgrade, and whether a reboot is needed",
        "Orphaned packages, AUR or locally built packages, and .pacnew files",
        "Installed programs and libraries that no longer match their package (daily)",
        "Programs and service files in system folders that no package owns",
    ],
    "network": [
        "Whether the ufw firewall is on and denies incoming connections by default",
        "Every listening port, judged against the firewall",
        "Databases, the Docker API, VNC and similar services reachable from other machines",
        "SSH exposure and brute-force protection, and Docker ports published on all interfaces",
        "Whether the firewall also covers IPv6",
        "Samba and NFS shares open without a password",
        "How well systemd sandboxes the services other machines can reach",
        "LLMNR, remote desktop tools, and outbound connections on unusual ports",
        "Cloudflare Tunnel routes and a login test of each public hostname",
        "Minecraft server settings, if you run one",
    ],
    "system": [
        "SSH server settings, SSH keys that can log in as you, and ~/.ssh permissions",
        "Passwordless sudo, risky accounts and docker group members",
        "Programs with root permissions (SUID) outside the usual places",
        "Autostart entries, services, cron jobs and recently changed startup files",
        "Kernel hardening settings, AppArmor or SELinux, and firmware age",
        "Package signature checking and HTTPS mirrors in pacman",
        "Whether the clock is kept in sync",
        "Docker container risks, and SSH, sudo and su login activity",
    ],
    "files": [
        "Programs in temp folders and suspicious desktop launchers",
        "Credential files other users can read, and secrets in shell history",
        "Git saving passwords in plain text (credential.helper store)",
        "Full file scan: setuid, world-writable and hidden programs, optional ClamAV",
        "Secrets committed to git repos (weekly, with gitleaks)",
    ],
    "changes": [
        "A snapshot of SSH keys, users, admin groups, sudo, PAM, sshd and cron config",
        "Services, timers, autostart entries and shell startup files",
        "Listening ports, firewall rules, tunnel routes and Docker containers",
        "Checked every 5 minutes. Anything new stays flagged until you press Accept changes",
    ],
    "opsec": [
        "Disk and swap encryption, and Secure Boot",
        "Screen lock settings",
        "Whether DNS lookups are encrypted, and Mullvad VPN status",
        "Tailscale devices, including other people's",
        "SSH keys without a passphrase, and SSH agent forwarding",
        "Clipboard history and crash dumps on disk, Bluetooth, KDE Connect, camera and mic in use",
        "Open Wi-Fi networks joined automatically, and Flatpak apps with wide file access",
    ],
}

FAQ = [
    ("Does PacWardX send my data anywhere?",
     "No. There's no telemetry or account. Results stay in ~/.local/share/pacwardx, readable only by you. The only "
     "network traffic comes from update checks (your mirrors, the Arch security tracker and the AUR) and, if you "
     "run Cloudflare Tunnel, one anonymous request to each of your own hostnames."),
    ("Why does it need a root helper?",
     "Some things can only be read as root, like which program owns a port, firewall rules and auth logs. The "
     "helper has a fixed list of read-only commands and nothing else. Without it, those checks are skipped."),
    ("A finding is wrong, or it's something I did on purpose.",
     "Select it and press Ignore. It stops counting toward the score and alerts, stays listed dimmed, and you can "
     "undo it here or in Settings. Under Changes, Accept changes records the current state as normal. Real false "
     "alarms are worth reporting as an issue on GitHub."),
    ("Can I use it from the terminal or a script?",
     "Yes. pacwardx scan prints the results (add --json for scripts) and exits 0 when nothing needs fixing, 1-3 for "
     "the worst severity found, and 4 on error. pacwardx report prints a shareable report, pacwardx ignore ID hides a "
     "finding, and pacwardx --help lists the rest."),
    ("What does History show?",
     "One row per scan. Select a row to see what was open then, what was new since the scan before, and what had "
     "been resolved."),
    ("Is it safe to run a suggested fix?",
     "Read it first. Fixes are suggestions for a typical setup. Some change firewall, SSH or login settings and "
     "can lock you out if they don't suit yours."),
    ("How do I remove PacWardX?",
     "Arch package: sudo pacman -R pacwardx. Git checkout: bash packaging/install.sh uninstall. To also remove your results and settings, use Delete results and "
     "history in Settings, then delete ~/.config/pacwardx."),
]

TROUBLESHOOTING = [
    ("“Background service off”",
     "Scans then only run while the window is open. Start the service with: "
     "systemctl --user enable --now pacwardx-daemon"),
    ("“Root helper unavailable” or checks marked as not inspected",
     "From a git checkout, install or update it by re-running: bash packaging/install.sh. With the Arch "
     "package, add yourself to the pacwardx group: sudo usermod -aG pacwardx $USER, then log out and back in."),
    ("A check says a tool isn't installed",
     "Install it with pacman (the Welcome page lists the commands), or ignore it. That check is simply skipped."),
]

TOOLS = [
    # (command to look for, what it adds, install command, required?)
    ("ufw", "Firewall checks", "sudo pacman -S ufw && sudo ufw enable", True),
    ("checkupdates", "Pending update checks", "sudo pacman -S pacman-contrib", True),
    ("arch-audit", "Known vulnerability checks", "sudo pacman -S arch-audit", True),
    ("gitleaks", "Secrets committed to git repos (optional)", "sudo pacman -S gitleaks", False),
    ("clamscan", "Virus scan during file scans (optional)", "sudo pacman -S clamav", False),
]

# "Learn more" links: a finding title pattern -> an ArchWiki page. First match wins.
WIKI = "https://wiki.archlinux.org/title/"
LEARN_MORE = [
    (r"login guessing", "Sshguard"),
    (r"firewall|ufw", "Uncomplicated_Firewall"),
    (r"signature", "Pacman/Package_signing"),
    (r"mirror", "Mirrors"),
    (r"samba", "Samba"),
    (r"\bnfs\b", "NFS"),
    (r"flatpak", "Flatpak"),
    (r"apparmor|selinux", "AppArmor"),
    (r"wi-fi", "NetworkManager"),
    (r"clock|time sync", "System_time"),
    (r"git saves|git-credentials", "Git"),
    (r"sandboxing", "Security"),
    (r"ssh key|ssh private key|authorized_keys|~/\.ssh|agent forwarding", "SSH_keys"),
    (r"\bssh\b|x11 forwarding", "OpenSSH"),
    (r"sudo|uid-0|empty password|accounts can log in|su attempts", "Sudo"),
    (r"pacnew|pacsave", "Pacman/Pacnew_and_Pacsave"),
    (r"orphaned packages|packaged files|package-file|belongs to a package|aren't owned by any package|"
     r"differ from their package|match their packages", "Pacman/Tips_and_tricks"),
    (r"\baur\b", "Arch_User_Repository"),
    (r"up to date|upgrade|update check|reboot needed|kernel", "System_maintenance"),
    (r"swap", "Dm-crypt/Swap_encryption"),
    (r"encrypt", "Dm-crypt"),
    (r"secure boot|legacy bios", "Unified_Extensible_Firmware_Interface/Secure_Boot"),
    (r"firmware", "Fwupd"),
    (r"docker|container", "Docker"),
    (r"clamav", "ClamAV"),
    (r"tailscale|tailnet", "Tailscale"),
    (r"bluetooth", "Bluetooth"),
    (r"dns|llmnr|systemd-resolve", "Systemd-resolved"),
    (r"\.local\b", "Avahi"),
    (r"screen .*lock|locks after", "Session_lock"),
    (r"crash dumps", "Core_dump"),
    (r"cron", "Cron"),
    (r"vulnerab|advisories|cve", "Security"),
    (r"kptr_restrict|ptrace_scope|ip forwarding|suid|setuid|world-writable", "Security"),
]


def learn_more(title: str) -> str | None:
    """ArchWiki page for a finding, or None when there's no good match."""
    t = title.lower()
    for pattern, page in LEARN_MORE:
        if re.search(pattern, t):
            return WIKI + page
    return None
