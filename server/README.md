# Remote RF Linux Server

A python codebase to host the remoteRF Platform. 

Courtesy of Wireless Lab @ UCLA. - Ethan Ge

## Prerequisites

- **Local Linux Computer**: You will need a linux based machine to run the server, along with the networking that goes along with it.

- **Python 3.12 or later**: This codebase requires Python 3.12+. If you don’t have Python installed, you can download it from the [official Python website](https://www.python.org/downloads/).
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

## Run Time

Once your basic config is setup, you can begin testing the basics of the server! 

```bash
    RRRFserver  # Start the server
```

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

- **Server Certificates**: Confirm that the server certs were generated with the right IPs, and that the existing server certs weren't expired. If you are not sure how to check them, just regenerate them. Remember that if you do regenerate you will need to give the client a exact copy of those certs as well.

- **Local Firewall**: Some distros come with default firewall settings that block traffic on specific ports. Make sure that your firewall settings permit traffic to and from the server.

- **Port Forwarding**: If you are using this on a private network, you will need to configure port forwarding on your router in order for external networks to access the server.

- **ISP Firewall**: Some ISPs may not have static IPs. You will need to contact them regarding it. If doing this on UCLA Campus, they block and manage much of the traffic. You will need to submit a [Firewall Access Form](https://www.seasnet.ucla.edu/firewall-access-request/).