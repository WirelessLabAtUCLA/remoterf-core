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

## HostRF Config

`hostrf` stores its config **repo-locally** under: `./.config/`

### 1) Point this host at a RemoteRF server

HostRF requires a RemoteRF Server already setup. See RemoteRF-Server for additional details.

```bash
hostrf --config --addr <host:port>
# example:
hostrf -c -a 164.97.201.67:5000
```

Inspect/Reset server target:

```bash
hostrf -c -a --show         # Show addr 
hostrf -c -a --wipe -y      # Wipe config params     
```