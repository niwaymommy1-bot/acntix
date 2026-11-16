#!/bin/bash
# install-cld-scripts.sh
# Installs/updates the CLD custom scripts from GitHub into every Acunetix
# install on this machine, sets the scanner thread count, then restarts Acunetix.
#
# Usage:  sudo bash install-cld-scripts.sh            (threads = 8)
#         sudo bash install-cld-scripts.sh 40         (threads = 40)
#
# Re-run it any time: new scripts added to the repo are installed and
# changed ones are updated.

REPO="niwaymommy1-bot/acntix"
BRANCH="main"
THREADS="${1:-8}"

# ---- run as root -------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
    exec sudo bash "$0" "$@"
fi
set -u

if ! [[ "$THREADS" =~ ^[0-9]+$ ]] || [ "$THREADS" -lt 1 ]; then
    echo "Threads must be a positive number (got: $THREADS)"; exit 1
fi

# ---- download the repo -------------------------------------------------
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
echo "[*] Downloading $REPO ($BRANCH)..."
if ! curl -fsSL "https://codeload.github.com/$REPO/tar.gz/refs/heads/$BRANCH" -o "$WORK/repo.tgz"; then
    echo "[!] Download failed (branch '$BRANCH' missing or no internet)"; exit 1
fi
mkdir "$WORK/src" && tar -xzf "$WORK/repo.tgz" -C "$WORK/src" --strip-components=1
mapfile -t SCRIPTS < <(find "$WORK/src" -maxdepth 1 -type f -name '*.js' | sort)
if [ ${#SCRIPTS[@]} -eq 0 ]; then
    echo "[!] No .js scripts found in the repo"; exit 1
fi
echo "[*] Found ${#SCRIPTS[@]} script(s) in the repo"

# Fix: give each alert a unique 'parameter' so Acunetix does not merge
# alerts from different scripts that all report at the site root.
fix_script() {
    sed -i -E "/typeId: 'custom.xml',/{n;/parameter:/!s/^(\s*)path: (.*),$/&\n\1parameter: 'CLD ' + \2,/}" "$1"
    sed -i "s/parameter: 'CLD ' + hits\[0\].path,/parameter: 'CLD ' + title,/" "$1"
}
for f in "${SCRIPTS[@]}"; do fix_script "$f"; done

# ---- find every Acunetix install ---------------------------------------
mapfile -t INSTALLS < <(find /home /root /opt -maxdepth 3 -type d -name '.acunetix' 2>/dev/null)
if [ ${#INSTALLS[@]} -eq 0 ]; then
    echo "[!] No Acunetix install found (looked for */.acunetix in /home, /root, /opt)"; exit 1
fi

for BASE in "${INSTALLS[@]}"; do
    echo
    echo "=== $BASE"
    OWNER=$(stat -c '%u' "$BASE"); GROUP=$(stat -c '%g' "$BASE")

    # 1. custom scripts
    DEST="$BASE/data/custom-scripts/target"
    mkdir -p "$DEST"
    for f in "${SCRIPTS[@]}"; do
        name=$(basename "$f")
        if [ ! -f "$DEST/$name" ]; then
            echo "  [+] new      $name"
        elif ! cmp -s "$f" "$DEST/$name"; then
            echo "  [~] updated  $name"
        else
            echo "  [=] same     $name"
        fi
        install -o "$OWNER" -g "$GROUP" -m 664 "$f" "$DEST/$name"
    done

    # 2. threads
    SET="$BASE/data/general/settings.xml"
    if [ -f "$SET" ]; then
        [ -f "$SET.orig" ] || cp -p "$SET" "$SET.orig"
        sed -i "0,/<Threads>[0-9]*<\/Threads>/s//<Threads>$THREADS<\/Threads>/" "$SET"
        echo "  [*] threads  $(grep -m1 -o '<Threads>[0-9]*</Threads>' "$SET")"
    else
        echo "  [!] settings.xml not found, threads not changed"
    fi
done

# ---- restart Acunetix --------------------------------------------------
echo
if systemctl list-unit-files 2>/dev/null | grep -q '^acunetix'; then
    echo "[*] Restarting acunetix service..."
    systemctl restart acunetix && sleep 3 && systemctl --no-pager --lines=0 status acunetix | head -3
else
    # No systemd service (e.g. Cloud Shell): restart the supervisor directly
    for BASE in "${INSTALLS[@]}"; do
        OWNER=$(stat -c '%u' "$BASE"); GROUP=$(stat -c '%g' "$BASE")
        HOMEDIR=$(dirname "$BASE")
        echo "[*] Restarting Acunetix supervisor for $BASE..."
        pkill -u "$OWNER" -f "$BASE/supervisor" 2>/dev/null
        for i in $(seq 1 30); do pgrep -u "$OWNER" -f "$BASE/supervisor" >/dev/null || break; sleep 1; done
        pkill -9 -u "$OWNER" -f "$BASE/supervisor" 2>/dev/null
        sleep 2
        (cd /tmp && env HOME="$HOMEDIR" USER="$(basename "$HOMEDIR")" \
            setpriv --reuid="$OWNER" --regid="$GROUP" --clear-groups \
            bash -c "cd '$BASE' && ./supervisor run --conf '$BASE/supervisor.yaml'" \
            > /tmp/acunetix.log 2>&1 &)
    done
fi

echo "[*] Waiting for the web UI on port 3443..."
UP=0
for i in $(seq 1 60); do
    if curl -sk -o /dev/null https://127.0.0.1:3443/; then UP=1; break; fi
    sleep 3
done
if [ "$UP" -ne 1 ]; then
    echo "[!] Acunetix did not answer on 3443 within 3 minutes. Check /tmp/acunetix.log"
    exit 1
fi
echo "[OK] Acunetix is up."

# ---- Cloudflare tunnel (public URL for the UI and the API) -------------
CF=/usr/local/bin/cloudflared
CFLOG=/tmp/cloudflared.log
if [ ! -x "$CF" ]; then
    echo "[*] Downloading cloudflared..."
    curl -fsSL -o "$CF" https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
        && chmod +x "$CF" || { echo "[!] cloudflared download failed"; exit 1; }
fi
pkill -f "$CF tunnel" 2>/dev/null; sleep 1
: > "$CFLOG"
nohup "$CF" tunnel --no-autoupdate --url https://localhost:3443 --no-tls-verify > "$CFLOG" 2>&1 &
URL=""
for i in $(seq 1 30); do
    URL=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$CFLOG" | head -1)
    [ -n "$URL" ] && break
    sleep 2
done

echo
echo "=================== RESULT ==================="
echo " Custom scripts : ${#SCRIPTS[@]} installed from $REPO"
echo " Threads        : $THREADS"
echo " Acunetix       : running"
if [ -n "$URL" ]; then
    echo " Public URL     : $URL"
    echo " API base       : $URL/api/v1"
else
    echo " Public URL     : not ready yet - check $CFLOG"
fi
echo "=============================================="
