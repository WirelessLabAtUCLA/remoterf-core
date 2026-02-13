# RemoteRF Host (hostrf) — Linux Setup

This guide installs Miniconda, creates a conda environment named `hostrf`, installs dependencies, and verifies the install on Ubuntu Server 24.04 LTS Linux.

> Notes
> - These commands assume an **APT-based** distro (Ubuntu/Debian/Raspberry Pi OS 64-bit).  
> - For non-APT distros (Fedora/Arch), you’ll need equivalent system packages.

---

## 0) Raspberry pi setup:
Raspberry pi Imager -> Install Ubuntu Server 24.04 LTS -> Boot up raspberry pi on SD card.

## 1) System Prerequisites (APT)

Update and install required system packages:

```bash
sudo apt update
sudo apt install -y curl ca-certificates bzip2 git build-essential
sudo apt install -y libusb-1.0-0 udev
````

Optional: confirm you’re on the expected architecture:

```bash
uname -m
```

* `x86_64` → Intel/AMD
* `aarch64` → ARM64 (Raspberry Pi 64-bit, some servers)

---

## 2) Install Miniconda

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

---

## 3) Create the Conda Environment

### 3.1 Create `environment.yml`

Create a file named `environment.yml` in your project directory:

```bash
cat > environment.yml <<'EOF'
name: hostrf
channels:
  - conda-forge
  - defaults

dependencies:
  - python=3.10
  - pip
  - setuptools
  - wheel

  - grpcio
  - protobuf
  - python-dotenv

  - numpy
  - scipy

  - libiio
  - pylibiio
  - libusb

  - pip:
      - pyadi-iio
      - remoterf-host
EOF
```

### 3.2 Create the environment

```bash
conda env create -f environment.yml
```

### 3.3 Activate it

```bash
conda activate hostrf
```

---

## 4) Verify Installation

### 4.1 Confirm Python version

```bash
python --version
```

Expected: `Python 3.10.x`

### 4.2 Verify core dependencies

```bash
python -c "import grpc, google.protobuf, dotenv, numpy, scipy; print('core deps ok')"
```

### 4.3 Verify IIO + ADI stack

```bash
python -c "import iio; import adi; print('iio + pyadi-iio ok')"
```

### 4.4 Verify `remoterf-host`

```bash
python -c "import remoteRF_host; print('remoterf-host ok')"
```

---

## 5) Common Operations

### Activate later (new terminal)

```bash
source "$HOME/miniconda3/etc/profile.d/conda.sh"
conda activate hostrf
```

### Update environment from `environment.yml`

```bash
conda env update -n hostrf -f environment.yml --prune
```

### Remove the environment

```bash
conda env remove -n hostrf
```

---

## 6) Troubleshooting

### `conda env create` is very slow (common on Raspberry Pi)

Install `mamba` and use it to create the environment:

```bash
conda install -n base -c conda-forge mamba
mamba env create -f environment.yml
```

### Missing packages on ARM / install errors for `libiio` / `pylibiio`

On some ARM setups, conda-forge availability can vary. If `conda env create` fails on those:

1. Remove `libiio` / `pylibiio` from `environment.yml`
2. Install system packages instead:

```bash
sudo apt install -y libiio0 libiio-dev
```