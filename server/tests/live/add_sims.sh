#!/bin/bash
# add_sims.sh <venv dir> <group name>: SimSDR-2..5 as devices 98..95, whitelisted in the shared group
set -e
for i in 2 3 4 5; do id=$((100-i)); grep -q "device_id: $id\$" ~/.config/remoterf/devices.yml || printf -- "- device_id: $id\n  device_type: sim_sdr\n  name: SimSDR-$i\n  init: {}\n" >> ~/.config/remoterf/devices.yml; done
~/$1/venv/bin/python - "$2" <<'PY' 2>&1 | grep -v '^Driver\|^Warning'
import sqlite3, os, json, sys
u = sqlite3.connect(os.path.expanduser('~/.config/remoterf/db/usergroups.db'))
for gid, name, wl in u.execute('select group_id, group_name, devices_whitelist from UserGroups').fetchall():
    ids = json.loads(wl) if wl.strip().startswith('[') else [int(x) for x in wl.split(',') if x.strip()]
    if name == sys.argv[1]:
        ids = sorted(set(ids) | {95, 96, 97, 98, 99}); u.execute('update UserGroups set devices_whitelist=? where group_id=?', (json.dumps(ids), gid))
    print(gid, name, ids)
u.commit()
PY
tmux -L remoterf-server send-keys -t server 'reload devices' Enter; sleep 6
tmux -L remoterf-server send-keys -t server 'devices list' Enter; sleep 4
tmux -L remoterf-server capture-pane -p -t server | grep -E 'SimSDR' | tail -5
