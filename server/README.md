# Remote RF Server Guide (Linux)

## Environment and setup

This guide installs Miniconda, installs **mamba**, creates a conda env named `remoterf`, installs dependencies, and verifies the install on Ubuntu Server 24.04 LTS.

* This guide is done **APT-based** distro (Ubuntu/Debian/Raspberry Pi OS 64-bit).

### 1) System Prerequisites

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

### 3) Create the Environment

```bash
mamba create -n remoterf -y -c conda-forge -c defaults  python=3.10 pip setuptools wheel grpcio protobuf python-dotenv numpy scipy libiio pylibiio libusb

conda activate remoterf
python -m pip install -U pip
python -m pip install pyadi-iio remoterf-server
```

## Server Config

Depending on your IT/ISP setup, this will vary, but regardless, you will need a static dial name, whether that be a IP address or a DNS.

### Generate CA Certificates

If direct IP connection: (force overrides existing)
```bash
serverrf --gen-certs 192.168.1.50 --days 3650 --force
```

If using DNS: (todo: DNS on client side)
```bash
serverrf --gen-certs 192.168.1.50 --dns remoterf.local --days 3650 --force
```

Confirm/View:
```bash
serverrf --show-certs
```

### Specify Outward facing Ports

By default, the users expect to adjacent ports. Thus, it is recommended to do the following:

```bash
# examples
serverrf --config --main-port 61000 --cert-port 61001
serverrf --config --main-port 20000 --cert-port 20001
serverrf --config --main-port 32000 --cert-port 32001
```

Confirm/View:
```bash
serverrf --config --show
```

## Testing Connection

The server now should be functional in its most basic form. In the same conda env:

```bash
serverrf --serve
```

If you see something along the lines of: self.socket.bind(self.server_address) PermissionError: [Errno 13] Permission Denied, make sure the ports you are using are not OS reserved (<1024)

### Confirm it works locally

<!-- In a new terminal:

```bash
mamba create -n local_testing -y python=3.10 pip
conda activate local_testing
pip install remoterf
```

Testing: In the remoterf env run: -->

Start the server:
```bash
serverrf -s
```
Take note of the Local IP and Local Port, for example, if you see:

```bash
Local IP: 164.67.195.210
Local Port: 61000
```

then run the below on a seperate terminal (make sure to keep serverrf -s RUNNING!)

Confirm that its reachable:

```bash
nc -vz 164.67.195.210 61000
nc -vz 164.67.195.210 61001
```

<!-- ```bash
remoterf -c -a 164.67.195.210:61000
```

If sucessful, it should look something like this:

```bash
gRPC target : 164.67.195.210:61000
cert port   : 164.67.195.210:61001
CA cert     : /home/remoterf-dev/.config/remoterf/certs/default.crt
env file    : /home/remoterf-dev/.config/remoterf/.env
```

If it fails, please troubleshoot, and make sure that the serverrf -s is actually running, and that you have no firewalls, etc.

Cleanup:
```bash
conda env remove -n local_testing
``` -->

### Network Testing

Same test, but on a different computer. Works for UNIX based machines:

Confirm that the Server is reachable:
```bash
nc -vz 164.67.195.210 61000
nc -vz 164.67.195.210 61001
```

You most likely will need to port forward, etc.

Troubleshooting:
Some distros come with default firewall settings that block traffic on specific ports. Make sure that your firewall settings permit traffic to and from the server. Depending on the setup, you may also have ISP firewalls.

## Server Device Configuration

Currently, only Adalm Plutos are supported.

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

The below should work as intended now:
```bash
iio_info -s
```

Look for 'serial='. Take note of this serial.

```bash
serverrf --device --add --pluto <device_id:name:serial>

# example
serverrf --device --add --pluto 0:pluto_0:104473f6
serverrf --device --add --pluto "1:Pluto SDR (OTA):58472j"
```

Run the below to check if this new device exists:
```bash
serverrf --device --show
```

Run the below to edit names of existing devices:
```bash
serverrf -d --edit-name 0 "New Name"
```

Note that all device and server config parameters need a 'restart' to take affect (ctrl + c -> serverrf -s).

## Server Runtime Configuration

After running `serverrf --serve`, you’ll enter the **RemoteRF Server Shell**. This interactive shell is used for runtime administration: managing users, devices, reservations, user groups, and enrollment codes.

---

#### Server

* `help` / `h` — Show help
* `clear` — Clear the screen
* `status` — Show server status (uptime / bind info)
* `quit` / `exit` — Exit the server shell

---

#### Users

* `users list` — List all accounts
* `users manage` — Manage a specific user 
* `users purge` — Delete **all** users

---

#### Devices

* `devices list` — List all devices

---

#### Reservations

* `reservations list` — List all reservations
* `reservations purge` — Delete **all** reservations

---

#### Groups

* `groups list` — List user groups
* `groups create` — Create a user group *(interactive)*
* `groups edit` — Edit a user group *(interactive)*
* `groups delete` — Delete a user group *(interactive)*
* `groups csv` - Export all groups as a CSV

---

#### Enrollment Codes

* `codes list` — List enrollment codes
* `codes create` — Create enrollment codes *(interactive)*
* `codes delete` — Delete an enrollment code *(interactive)*
* `codes csv` - Export all codes as a CSV

---

#### Database

* `db purge` — Remove all database entries

---

## 
todo:
<!-- Adding plutos via the CLI -->
<!-- Testing functionality (disregarding Host pipeline) -->
<!-- Clean up serverrf CLI + basic documentation for all commands, usergroups, export codes by CSV. -->

HostRF meta data -> push upon connection + retry connection on host side.

ServerRF display meta data as part of devices list / reservation + online/activity status (appended into device name) + (plus host side warning if the device id is NOT globally unique!)

set_device token (virtual devices) + routing/relay to proper host (multiplexed)

User side testing + integration

hostrf side CLI/server (basically just device list)

edge case testing (disconnected hosts, disconnected server, many users using multiple devices, multi-host)

<!-- HostRF integration -> Host directory, device routing, dynamic reservation pulling, with activity/status (online, offline, etc.)  -->

Cleanup code comments.

Update Ian with installation demo (try myself first on the NUC once!) for both server and host.

Nice to have (later):
Activity/stats?
Ability to remotely manage groups and codes as admin.
Choice to choose usergroup/code by either int id or string name. (too lazy)

todo: Specify/Pull user side --config CLI pointing to this server + debug for connection sake (later)


<!-- # Remote RF Linux Server

A python codebase to host the remoteRF Platform. 

Courtesy of Wireless Lab @ UCLA. - Ethan Ge

## Prerequisites

- **Local Linux Computer**: You will need a linux based machine to run the server, along with the networking that goes along with it.

- **Python 3.12**: Honestly I am not sure what minimum version is required. But 3.12 for sure works. If you don’t have Python installed, you can download it from the [official Python website](https://www.python.org/downloads/).
To check your current Python version, open a terminal and run:

```bash
python --version
```

- **Adalm Pluto Python Drivers**: You will need to install this if you wish to use the adalm pluto SDR. [Adalm Pluto Python Drivers](https://pysdr.org/content/pluto.html).

- **Other Devices**: At the moment, although a couple other devices are loosely supported, the Pluto is the only 'full support' device. More can be easily added though.

## Installation

### **Note**: 
These instructions are confirmed to be working on Fedora LTS Server build. Although nothing should need changing on different distros, I cannot confirm nor deny that.

### **Clone Repo**: 
First clone the server repo [here](https://github.com/WirelessLabAtUCLA/RemoteRF-Server).

### **Python Dependencies**: 
Navigate to the cloned repo. Run the below commands. Mind that a python virtual environment `VENV` is recommended, although given device drivers, it may not be the easiest.

```bash
    python3 -m venv venv        # Create venv folder
    source venv/bin/activate    # Activate venv

    pip install setuptools -e . # Auto installs dependencies

    RRRFserver                  # Run Remote RF Server
```
If you have errors, such as `ModuleNotFoundError: No module named 'adi'`, yet you are able to use the adi package elsewhere, such as in the global interpreter, you will need to update your python path to include the adi package, which you should've installed earlier from [here](https://pysdr.org/content/pluto.html).

If you are too lazy to do so, you can just repeat the same steps but on the global python interpreter, which should solve the issue, albeit a less clean solution.

## Configuration

Now onto the configuration of the server for use. Server script needs to be restarted for config to take place.

### Network parameters:
The server requires a specified port as well as a manual IP to be set. You can do an online search for "how to input manual IP address for OS TYPE".

Navigate to `src/remoteRF_server/certs` directory.
```bash
    cd src/remoteRF_server/certs    # From repo root

    openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt -subj "/CN=XXX.XX.XXX.XXX" -addext "subjectAltName=IP:XXX.XX.XXX.XXX"    # Generate the certs. Replace XXX.XX.XXX.XXX with the server IP.
```
Navigate to `src/remoteRF_server/server/.env.server`.
```bash
    GRPC_PORT='XXXXX'   # Replace XXXXX with the server port.
```
Copy the internals of `/certs`, and replace the remoteRF-Client cert folder with these new certificates. This is done as **BOTH** the client and server need to have access to the same generated certificates for secure HTTPs transfer.

### Device parameters:

Navigate to `src/remoteRF_server/server/device_manager.py`. Scroll down until you see:
```python
    devices = { # device, salt, hash
        0: (connect_pluto(usb='1.6.5'), '', ''),
        1: (connect_pluto(usb='1.7.5'), '', ''),
        # ...
    }
```
To add more devices, simply duplicate the item and increment the device id. You also need to configure the usb port. To find this value, run this in the terminal once you have connected your desired devices.
```bash
    iio_info -s # displays usb port info
```
```bash
    Available contexts:
    	0: (jc42,coretemp,pch_skylake,nouveau,acpitz,jc42,dell_smm,hidpp_battery_0,nvme on Dell Inc.) [local:]
    	1: 0456:b673 (Analog Devices Inc. PlutoSDR (ADALM-PLUTO)), serial=10447392da110010f9ff1500612ff8ecb0 [usb:1.6.5]    
        # Use this `usb:1.6.5` as the input for the device init
```
Under `devices` there is also `device_info`. Update this accordingly. This is what is displayed when users request to see what devices there are.

Remember to update default permissions and the like! Otherwise users won't be able to add the new devices.

### Permission parameters:

In the repo, navigate to `src/remoteRF_server/server/acc_perms.py`. You should see:
```python
    class userperms:
        def __init__(self): # default user perms settings
            self.id = 'user'
            self.max_reservations = 1
            self.max_reservation_time_sec = 3600
            self.devices_allowed = [0, 1]   # device ID
```
Here, you can set the default user perms. This default is given to all 'normal users', and is also the permission level when users first make their accounts. For the other two tiers of users, they are configured on run time when the server is running. The server saves all run time changes so no data hypothetically can be lost.

### .Proto regen:
Only needed if, well, you need to update the base networking.
```bash
pip install --upgrade grpcio grpcio-tools protobuf

cd src/remoteRF_server/common/grpc
python -m grpc_tools.protoc \
      -I=. \
      --python_out=. \
      --grpc_python_out=. \
      grpc.proto
```

## Time to Serve!

Once your basic config is setup, you can begin testing the basics of the server! 

```bash
    RRRFserver  # Start the server
```

Given my weird setup, this is what I did to make it work:
New Terminal
cd Documents/GitHub/RemoteRF-Server
sudo pip install -e . (don't use pip3)
sudo RRRFserver

IF the changes you make don't seem to apply ...
which RRRFserver
What worked for me (if u accidently use pip3)
sudo python3 -m pip uninstall RemoteRF-Server (destroy pip3)

Bruh ....

python3 -m pip uninstall -y remoteRF_server RRRFserver || true
rm -f ~/.local/bin/RRRFserver
hash -r

python3 -m pip install -e . --user --force-reinstall
hash -r

Type `help` to see the list of commands. They are pretty self explanatory. Run them and try it out! You can use arrow keys to cycle commands.

```bash
'exit' - Stop server.
'help' - Help.
'clear' - Clear terminal screen.
'printa' - Print all accounts
'printd' - Print all devices
'printp' - Print all perms
'printr' - Print all reservations
'rm aa' - Remove all accounts
'rm a' - Remove one account
```

Follow the [README](https://github.com/WirelessLabAtUCLA/RemoteRF-Client/blob/main/README.md) on this repo to configure the client side.

I would suggest first trying to connect locally (on the same machine), and then remotely. You do not need the VPN if you are testing locally or on LAN. If all goes well, the server should be now ready for use! 

**WARNING**: The current system distributes the private certificates. It is safe as UCLA wraps the network in a VPN, however if you open the server to all of the internet, this approach can be very dangerous.

## Troubleshooting
I had a variety of issues setting up the server. Here is a list of steps to take if the server refuses to connect:

### Server Certificates:
Confirm that the server certs were generated with the right IPs, and that the existing server certs weren't expired. If you are not sure how to check them, just regenerate them. Remember that if you do regenerate you will need to give the client a exact copy of those certs as well.

### Local Firewall: 
Some distros come with default firewall settings that block traffic on specific ports. Make sure that your firewall settings permit traffic to and from the server.

- **ISP Firewall**: If doing this on UCLA Campus, they block and manage much of the traffic. You will need to submit a [Firewall Access Form](https://www.seasnet.ucla.edu/firewall-access-request/). -->