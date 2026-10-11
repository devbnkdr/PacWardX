#!/usr/bin/env bash
# Installs PacWardX for the current user. Safe to re-run.
#   bash packaging/install.sh            install / update
#   bash packaging/install.sh uninstall  remove everything it created
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USER_NAME="$(id -un)"
PY="$(command -v python3)"
BIN="$HOME/.local/bin"
HELPER_DIR=/usr/local/lib/pacwardx
SUDOERS=/etc/sudoers.d/pacwardx
UNIT_DIR="$HOME/.config/systemd/user"
APPS="$HOME/.local/share/applications"
AUTOSTART="$HOME/.config/autostart"
ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"

if [[ "${1:-}" == "uninstall" ]]; then
  systemctl --user disable --now pacwardx-daemon.service 2>/dev/null || true
  rm -f "$UNIT_DIR/pacwardx-daemon.service" "$APPS/pacwardx.desktop" "$AUTOSTART/pacwardx-tray.desktop" \
        "$BIN/pacwardx" "$ICON_DIR/pacwardx.svg"
  systemctl --user daemon-reload
  echo "Removing root helper and sudoers rule (needs your password)…"
  sudo rm -rf "$HELPER_DIR" "$SUDOERS"
  echo "Uninstalled. Your data in ~/.local/share/pacwardx and ~/.config/pacwardx was kept."
  exit 0
fi

echo "==> Checking dependencies"
"$PY" -c "import PySide6" 2>/dev/null || { echo "PySide6 missing:  sudo pacman -S pyside6"; exit 1; }
for tool in checkupdates arch-audit; do
  command -v "$tool" >/dev/null || echo "   optional: $tool not found (pacman-contrib / arch-audit) — package checks will be partial"
done

echo "==> Launcher: $BIN/pacwardx"
mkdir -p "$BIN"
cat > "$BIN/pacwardx" <<EOF
#!/usr/bin/env bash
cd "$REPO" && exec "$PY" -m pacwardx "\$@"
EOF
chmod +x "$BIN/pacwardx"

echo "==> Icon + desktop entries"
mkdir -p "$ICON_DIR" "$APPS" "$AUTOSTART"
cp "$REPO/pacwardx/ui/pacwardx.svg" "$ICON_DIR/pacwardx.svg"
sed "s|@BIN@|$BIN/pacwardx|g" "$REPO/packaging/pacwardx.desktop" > "$APPS/pacwardx.desktop"
sed "s|@BIN@|$BIN/pacwardx|g" "$REPO/packaging/pacwardx-tray.desktop" > "$AUTOSTART/pacwardx-tray.desktop"
update-desktop-database "$APPS" 2>/dev/null || true

echo "==> Background service (systemd --user)"
mkdir -p "$UNIT_DIR"
sed -e "s|@REPO@|$REPO|g" -e "s|@PY@|$PY|g" "$REPO/packaging/pacwardx-daemon.service" > "$UNIT_DIR/pacwardx-daemon.service"
systemctl --user daemon-reload
systemctl --user enable --now pacwardx-daemon.service
sleep 1
systemctl --user --no-pager --lines=0 status pacwardx-daemon.service | head -3 || true

echo "==> Root helper (needs your password once)"
echo "    Installs $HELPER_DIR/pacwardx-priv (read-only, fixed subcommands) and allows"
echo "    '$USER_NAME' to run it without a password via $SUDOERS."
sudo install -d -m 755 "$HELPER_DIR"
sudo install -m 755 -o root -g root "$REPO/packaging/pacwardx-priv" "$HELPER_DIR/pacwardx-priv"
# The rule is written to a root-owned temp file so nothing running as you can change it
# between the visudo check and the install.
TMP="$(sudo mktemp)"
printf '%s ALL=(root) NOPASSWD: %s/pacwardx-priv\n' "$USER_NAME" "$HELPER_DIR" | sudo tee "$TMP" >/dev/null
if sudo visudo -cf "$TMP" >/dev/null; then
  sudo install -m 440 -o root -g root "$TMP" "$SUDOERS"
  sudo rm -f "$TMP"
else
  sudo rm -f "$TMP"
  echo "sudoers rule failed validation; not installed"; exit 1
fi
if sudo -n "$HELPER_DIR/pacwardx-priv" ping >/dev/null 2>&1; then
  echo "    helper OK"
else
  echo "    helper not reachable via sudo -n; check $SUDOERS"
fi

echo
echo "Done. Launch 'PacWardX' from the app menu, or run: pacwardx"
echo "It starts minimised to the tray at login. First scan runs ~20 s after the service starts."
