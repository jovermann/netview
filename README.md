netview - network status and local device list
=======

Netview is a GUI for monitoring the internet connection status, listing all devices on the local network and for controlling Tasmota Wifi sockets.

Features:

- Network Status tab:
  - Checking connectivity to the local router, DNS servers, and some well-known remote IPs and names.
  - Verify DNS is functional.
  - Check for portals.

- Local devices tab:
  - Scan the local /24 network and show all devices.
  - Use ARP cache and ping to discover all devices in less than a second.
  - Show IP, name, MAC, MAC vendor and some ports if available.
  - Link to device page if available.

- Tasmota sockets tab:
  - Scan the local network for Tasmota sockets. No configuration required.
  - Show on/off state and allow to toggle the switch.
  - Show power and energy values.
  - Link to device page.


Installation and running
------------------------

On macOS:

    brew install python@3.13
    brew install pyside

Run with:

    python3.13 netview.py

On Ubuntu/Linux:

    sudo apt update
    sudo apt install -y python3-venv python3-pip build-essential
    python3 -m venv .venv
    source .venv/bin/activate
    pip install --upgrade pip
    pip install PySide6

Run with:

    python3 netview.py

