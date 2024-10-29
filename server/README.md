# Remote RF Linux Server

A python codebase to host the remoteRF Platform. Courtesy of Wireless Lab @ UCLA. This setup/management guide is quite arduous, as not only do you need to setup the server, but also each of the drivers for each type of device. 

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

- **Note**: These instructions are confirmed to be working on Fedora LTS Server build. Although nothing should need changing on different distros, I cannot confirm nor deny that.

- **Clone Repo**: First clone the server repo [here](https://github.com/WirelessLabAtUCLA/RemoteRF-Server).

- **Python Dependencies**: Navigate to the cloned repo. Run the below commands. Mind that a python virtual environment `VENV` is highly recommended/required.

```bash
    python3 -m venv venv        # Create venv folder
    source venv/bin/activate    # Activate venv

    pip install 
```

## Troubleshooting
I had a variety of issues setting up the server. Here is a list of steps to take if the server refuses to connect:

- **Server Certificates**: Confirm that the server certs were generated with the right IPs, and that the existing server certs weren't expired. If you are not sure how to check them, just regenerate them. Remember that if you do regenerate you will need to give the client a exact copy of those certs as well.

- **Local Firewall**: Some distros come with default firewall settings that block traffic on specific ports. Make sure that your firewall settings permit traffic to and from the server.

- **ISP Firewall**: If doing this on UCLA Campus, they block and manage much of the traffic. You will need to submit a [Firewall Access Form](https://www.seasnet.ucla.edu/firewall-access-request/).