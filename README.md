netview
=======

Netview is a GUI showing the network connection status and listing devices on the local network.

Features:

- Network Status pane:
  - Checking connectivity to the local router, DNS servers, and some well-known remote IPs and names.
  - Verify DNS is functional.
  - Check for portals.

- Local devices pane:
  - Scan the local /24 network and show all devices.
  - Use ARP cache and ping to discover all devices in less than a second.
  - Show IP, name, MAC, MAC vendor and some ports if available.


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

