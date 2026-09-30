#!/usr/bin/env bash
# Bring a server installed as in the VPS guide up to date with its branch:
# pull, reinstall into the venv, refresh the service unit if it changed,
# restart, and wait until the dashboard answers again.
#
#   cd /opt/skyrouter/src && sudo git pull --ff-only && sudo bash deploy/skyrouter/update.sh
#
# Settings (/etc/skyrouter/router-manager.env) and data (/var/lib/skyrouter)
# are never touched.
set -euo pipefail

SRC=${SKYROUTER_SRC:-/opt/skyrouter/src}
VENV=${SKYROUTER_VENV:-/opt/skyrouter/venv}
UNIT=router-manager
UNIT_FILE=${SKYROUTER_UNIT_FILE:-/etc/systemd/system/$UNIT.service}
# The port pinned in the unit's ExecStart.
HEALTH_URL=http://127.0.0.1:8091/healthz

if [[ $(id -u) -ne 0 ]]; then
    echo "Run this with sudo." >&2
    exit 1
fi

cd "$SRC"
before=$(git rev-parse --short HEAD)
# --ff-only: code edited on the server stops the update instead of being merged.
git pull --ff-only
after=$(git rev-parse --short HEAD)

# A local path is always rebuilt and reinstalled, even at the same version.
"$VENV/bin/pip" install --quiet --disable-pip-version-check "$SRC"

if ! cmp -s "$SRC/deploy/skyrouter/$UNIT.service" "$UNIT_FILE"; then
    install -m 0644 "$SRC/deploy/skyrouter/$UNIT.service" "$UNIT_FILE"
    systemctl daemon-reload
    echo "Service unit updated."
fi

systemctl restart "$UNIT"

for _ in $(seq 1 30); do
    if health=$(curl -fsS --max-time 2 "$HEALTH_URL" 2>/dev/null); then
        echo "SkyRouter $before -> $after is running: $health"
        exit 0
    fi
    sleep 1
done

echo "SkyRouter did not answer on $HEALTH_URL after the restart." >&2
echo "See: sudo journalctl -u $UNIT -n 50 --no-pager" >&2
exit 1
