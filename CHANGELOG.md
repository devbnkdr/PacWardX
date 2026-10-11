# Changelog

## 0.1.0 — first public release

- Six check categories: Packages, Network, System, Files, Changes, and Privacy & OpSec.
- A background `systemd --user` scheduler, plus a change watcher that runs every 5 minutes.
- A read-only root helper with fixed subcommands, installed with a validated sudoers rule.
- A redesigned desktop app:
  - sidebar with status badges
  - overview with a score ring and severity chips
  - list and detail view for findings, with copyable fixes
  - grouped Settings with toggle switches
  - live light and dark appearance
- Tray icon that reflects the worst open finding.
- A Welcome page on first launch: what PacWardX does and doesn't do, a setup checklist with install commands,
  and a button to run the first scan.
- A Help page with severity levels, what each category checks, common questions and troubleshooting, plus a
  "What's checked" button on every category page.
- "Delete results and history" in Settings.
- Ignore a finding (with an optional note): it stays listed, dimmed, and stops counting. Undo it on the page or
  in Settings.
- Search and severity filter on every category page, and a "Learn more" link to the related ArchWiki page.
- History drill-down: select a scan to see what was open, what was new and what had been resolved.
- Optional weekly summary notification.
- Checks for exposed databases and the Docker API, SSH brute-force protection, IPv6 firewall gaps, Samba and
  NFS shares, service sandboxing, pacman signature checking and HTTPS mirrors, AppArmor/SELinux, time sync,
  SSH empty passwords, git plain-text credentials, open Wi-Fi networks and Flatpak file access.
- CLI: `pacwardx scan [--json] [--category]` with exit codes by severity, `pacwardx report [--full]`,
  `pacwardx accept`, `pacwardx ignore` / `unignore` / `ignored`, and `pacwardx --version`.
- Arch package build file (`packaging/arch/PKGBUILD`) and GitHub issue templates.
