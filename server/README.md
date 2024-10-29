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

- **Python Dependencies**: Here is the list of python package dependencies that are needed. Mind that a `python virtual environment` is highly recommended/required.

```bash
    pip install 
```