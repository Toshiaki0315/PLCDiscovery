"""
PLC Simulators - Software PLC for Testing

Provides software-based PLC simulators for testing the PLC Discovery tool
without physical PLC hardware.

Supported Protocols:
- SLMP (Mitsubishi MC Protocol)
- Modbus/TCP
- EtherNet/IP
- S7 (Siemens)
- FINS (Omron)

simulator_gui.py is a Tk front end (start / stop, edit and animate values);
control.py holds its headless part.
"""

__version__ = "1.0.0"
