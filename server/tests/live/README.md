# Live soak tooling (not collected by pytest)

Two labs on Global, each with simulated SDRs (`add_sims.sh <venv dir> <shared group>`),
a HOME user per worker, and the real Client library end to end.

- `soak_client.py` — one worker: login/register, cluster enroll, reserve a free
  `SimSDR*` of the partner, `ensure_driver`, stream `rx()` for `--minutes`,
  verifying every buffer (length, dtype, the tone at fs/8) and recording latency
  and which path carried each call. `--idle-seconds` sits idle mid-run to watch
  the owner close the path and the client re-punch.
- `soak_run.py fwd|rev --workers N --minutes M` — N workers at once, one summary
  line each; edit the hosts, register code and cluster codes at the top.
- `real_sdr.py` — a real cabled-loopback Pluto: reserve (partner with `--owner`,
  else the HOME's own), TX a tone, verify peak and SNR on RX for three tones,
  then `rx()` for `--minutes`. Run from `~/soak` next to `soak_client.py`.
- `real_ota.py --tx <alias> --rx <alias>[,<alias>]` — over the air between real
  radios (Pluto or USRP either side): two tones per LO, each RX must see the
  exact tone step. Aliases as listed to the user (partner devices 1000000+id).
- `native_punch.py` — the native Gate I punch from this machine to a HOME reached
  over its relay: tells a network that cannot punch from a partner-path bug.

Run on a lab box: `HOME=~/soak/home1 python soak_client.py --home <ip:port> --cert-port <p> ...`.
Results of 2026-09-24 are in `~/Documents/GitHub/remoterf-deployment-groups-live-report.md`.
