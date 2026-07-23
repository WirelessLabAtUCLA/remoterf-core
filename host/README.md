# RemoteRF Host (hostrf) — Linux Setup

## HostRF Installation

The guide is done/verified for Ubuntu Server/Desktop 24.04 LTS.

### 0) If Raspberry Pi

Raspberry Pi Imager → Install Ubuntu Server 24.04 LTS → Boot Raspberry Pi from SD card.

### 1) System Prerequisites (APT)

```bash
sudo apt update
sudo apt install -y curl ca-certificates bzip2 git build-essential
sudo apt install -y libusb-1.0-0 udev
```

Optional: confirm architecture:

```bash
uname -m
```

* `x86_64` → Intel/AMD
* `aarch64` → ARM64 (Raspberry Pi 64-bit, some servers)

---

### 2) Install Miniconda

### 2.1 Download the installer

#### x86_64

```bash
cd /tmp
curl -fsSLO https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
```

#### ARM64 (aarch64)

```bash
cd /tmp
curl -fsSLO https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-aarch64.sh
```

### 2.2 Install (non-interactive, recommended)

#### x86_64

```bash
bash Miniconda3-latest-Linux-x86_64.sh -b -p "$HOME/miniconda3"
```

#### ARM64 (aarch64)

```bash
bash Miniconda3-latest-Linux-aarch64.sh -b -p "$HOME/miniconda3"
```

### 2.3 Enable conda in your current shell

```bash
source "$HOME/miniconda3/etc/profile.d/conda.sh"
conda --version
```

> If you want conda available automatically in new terminals:
>
> ```bash
> "$HOME/miniconda3/bin/conda" init bash
> source ~/.bashrc
> ```

### 2.4 Install **mamba** (default solver)

```bash
conda install -n base -c conda-forge -y mamba
mamba --version
```

Might have to accept anaconda TOS.
```bash
conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main

conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r
```

### 3) Create the Environment (with mamba (faster))

```bash
mamba create -n hostrf -y -c conda-forge -c defaults  python=3.10 pip setuptools wheel grpcio protobuf python-dotenv numpy scipy libiio pylibiio libusb

conda activate hostrf
python -m pip install -U pip
python -m pip install pyadi-iio remoterf-host
```

```bash
sudo reboot now
```

## HostRF Config

Run the below for a comprehensive overview:
```bash
hostrf --help
```

To get hostrf up and running:

### 1) Point to a RemoteRF server

HostRF requires a RemoteRF Server already setup. See RemoteRF-Server for additional details.

`hostrf` stores its host config under: `~/.config/remoterf/host/`

Custom device drivers are loaded from: `~/.config/remoterf/drivers/`

```bash
hostrf --config --addr <host:port>
# example:
hostrf --config --addr 164.97.201.67:5000
hostrf --config --show
```

### 2) Set host parameters

On the remoterf server, run the below:

Example uses 'lab-host-01' as the host name.
It will return a valid command you can just copy and paste into the host CLI.

```bash
serverrf --host --token-create lab-host-01 --length 8
```

Given the parameters/tokens returned, run the below:

```bash
hostrf --host --set <hostname> \"TOKEN\"
#example:
hostrf --host --set lab-host-01 "UTzhag"
```

<!-- 164.67.195.207:61005 -->

### 3) Connect devices (Adalm Pluto)

To connect plutos to the server:

```bash
iio_info -s
```

If the pluto doesn't show up, yet the below works:

```bash
sudo iio_info -s
```

Run the below and reboot after: 

```bash
sudo groupadd -f plugdev
sudo usermod -aG plugdev "$USER"

sudo tee /etc/udev/rules.d/53-adi-usb.rules >/dev/null <<'EOF'
# Type the below in
SUBSYSTEM=="usb", ATTR{idVendor}=="0456", MODE="0660", GROUP="plugdev"
EOF

sudo udevadm control --reload-rules
sudo udevadm trigger
sudo reboot now
```


Look for a 'hw_serial: 104473'. Keep note of said serial per device.

Add pluto to device list. Understand that the device_id (int) needs to be GLOBALLY unique!

```bash
hostrf --device --add --pluto <id>:<device_name>:<hw_serial>

#Example
hostrf --device --add --pluto 10:"hostrf pluto 0":104473
```

For a Pluto running the MIMO schema, configure `devices.yml` with the schema device type:

```yaml
devices:
  - device_id: 11
    device_type: adalm_pluto_mimo
    name: hostrf pluto mimo 0
    init:
      serial: "104474"
```

Remove device:

```bash
hostrf --device --remove <id>
```

Show devices:
```bash
hostrf --device --show
```

Clear all device config:
```bash
hostrf --device --wipe
```

Run to start the host. You should be able to see host on the server if setup properly.
```bash
hostrf --serve
```

### 4) Connect an NI USRP-2901 / B200-family device

The machine connected to the radio must provide the UHD `4.10.0.0` Python
module. HostRF publishes the full USRP schema even when UHD is unavailable, but
opening a real Dynamic v2 session requires that exact supported UHD API.

Add a serial-bound inventory entry:

```bash
hostrf --device --add --usrp 7:usrp2901_lab:31A2B3C
hostrf --device --show
```

Equivalent `devices.yml`:

```yaml
devices:
  - device_id: 7
    device_type: usrp
    name: usrp2901_lab
    init:
      serial: 31A2B3C
```

Run `hostrf --serve` after the RemoteRF server has been upgraded with tunneled
Dynamic v2 support. Control calls, opaque handles, and `SampleDataV1` binary IQ
frames then use the existing authenticated host tunnel. HostRF closes native
USRP sessions automatically when a reservation ends or the tunnel disconnects.

Custom `usrp` schemas under `~/.config/remoterf/drivers/` take precedence over
the packaged default. No `usrp_policy.yml` file is required.
