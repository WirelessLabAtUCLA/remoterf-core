#!/bin/sh
# Install or upgrade the dev test lab: remoteRF-server with five simulated SDRs
# (SimSDR-1..5 = devices 99..95), run by systemd as `testlab`, joined to dev
# Global. Run as root on the dev VPS from a remoterf-core checkout:
#   sh tools/dev-smoke/setup-testlab.sh            # install/upgrade, (re)start
# Idempotent: config already in place is kept.
set -eu
REPO=$(cd "$(dirname "$0")/../.." && pwd)
T=/opt/remoterf-testlab
C=$T/.config/remoterf
# The broker dials only public addresses, so the lab binds the VPS address that
# testlab.dev.global.remoterf.net resolves to; ufw admits only the Docker network.
IP=$(getent ahostsv4 testlab.dev.global.remoterf.net | awk 'NR==1{print $1}')
ip -4 -o addr | grep -q " $IP/" || { echo "testlab.dev.global.remoterf.net -> '$IP' is not an address of this host" >&2; exit 1; }
RUN="sudo -u testlab -H env REMOTERF_GLOBAL_BROKER_ID=1b65277e-49e1-4091-b683-d69136f6bf2a REMOTERF_GLOBAL_DOMAIN=dev.global.remoterf.net REMOTERF_BIND_HOST=$IP"

id testlab >/dev/null 2>&1 || useradd --system --create-home --home-dir $T --shell /usr/sbin/nologin testlab
[ -x $T/venv/bin/python ] || $RUN python3 -m venv $T/venv
rm -rf $T/src && mkdir -p $T/src && cp -r "$REPO/server" "$REPO/packages" $T/src/ && chown -R testlab:testlab $T/src
$RUN nice $T/venv/bin/python -m pip install -q $T/src/packages/remoterf-federation-core $T/src/packages/remoterf-device-core $T/src/server

install -d -o testlab -g testlab -m 700 $T/.config $C $C/drivers
install -o testlab -g testlab -m 644 "$REPO/server/contrib/drivers/sim_sdr_schema.py" $C/drivers/
printf 'REMOTERF_GLOBAL_BROKER_ID=1b65277e-49e1-4091-b683-d69136f6bf2a\nREMOTERF_GLOBAL_DOMAIN=dev.global.remoterf.net\nREMOTERF_BIND_HOST=%s\n' "$IP" > $T/testlab.env
[ -f $C/server.env ] || $RUN sh -c "printf 'GRPC_PORT=12321\nCERT_PORT=12322\n' > $C/server.env"
$RUN sed -i "/^STATIC_IP=/d" $C/server.env && echo "STATIC_IP=$IP" | $RUN tee -a $C/server.env >/dev/null
[ -f $C/tos.env ] || $RUN sh -c "printf 'REMOTERF_TOS_ACKNOWLEDGED=true\nREMOTERF_TOS_VERSION=2026\n' > $C/tos.env"
[ -f $C/devices.yml ] || $RUN sh -c "printf 'devices:\n' > $C/devices.yml; for i in 1 2 3 4 5; do printf '  - device_id: %s\n    device_type: sim_sdr\n    name: SimSDR-%s\n    init: {}\n' \$((100-i)) \$i >> $C/devices.yml; done"
ufw delete allow proto tcp from 172.18.0.0/16 to 172.18.0.1 port 12321:12322 >/dev/null 2>&1 || true  # pre-public-bind rule
ufw status | grep -q "^$IP 12321:12322/tcp .*172.18.0.0/16" || ufw allow proto tcp from 172.18.0.0/16 to "$IP" port 12321:12322

install -m 644 "$REPO/tools/dev-smoke/remoterf-testlab.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable remoterf-testlab
systemctl restart remoterf-testlab
sleep 15
systemctl --no-pager --lines=15 status remoterf-testlab || true

# One public group holding the five sims: every dev Global account may reserve
# them (queued until the lab is in the `global` cluster).
$RUN $T/venv/bin/python - <<'PY'
from remoteRF_server.server.user_group_handler import user_group_handler as h
if not any(g["group_name"] == "sims" for g in h.get_all_user_groups(include_users=False) or []):
    print("created group", h.create_user_group(group_name="sims", devices_whitelist=[95, 96, 97, 98, 99],
                                               max_reservation_time_sec=1800, max_reservations=3, lifetime_sec=0))
PY
$RUN $T/venv/bin/serverrf groups public sims on || true
free -m
