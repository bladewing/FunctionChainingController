## Security Appliance Wrapper

Wrapper running on Security Appliance to communicate with the Function Chaining Controller to alert Controller of attacks.

## Prerequisites
The Wrapper is written in **_Python3_**.
These Python Packages need to be installed with pip3:

*flask, jwt (PyJWT)*

To install pip3 use following command:

`sudo apt-get install python3-pip`

Finally use pip3 to install the packages:

`sudo pip3 install flask PyJWT`

## Quickstart

After all prerequisites are installed, modify the config-file *wrapper.ini*. Then simply start the Wrapper with

`python3 startController.py`