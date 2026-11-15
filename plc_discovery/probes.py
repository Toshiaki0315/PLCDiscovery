"""
Protocol verification probes for discovery.

An open TCP port alone does not identify a PLC (e.g. port 5001 is also used
by NAS web interfaces). Each probe sends one harmless, read-only request of
the protocol and checks that the reply has the protocol's framing. An error
reply in the right format still counts: it proves the protocol is spoken.

All probes are synchronous (run them in an executor) and never write to the
device.
"""

import ipaddress
import logging
import os
import socket
import struct
from typing import Callable, Dict, Optional

from .config import Protocol

logger = logging.getLogger(__name__)


def _exchange(ip: str, port: int, request: bytes, timeout: float, min_len: int) -> Optional[bytes]:
    """Send one request and return the first reply bytes (None on failure)"""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request)
            data = b""
            while len(data) < min_len:
                chunk = sock.recv(512)
                if not chunk:
                    break
                data += chunk
            return data
    except OSError as e:
        logger.debug(f"Probe {ip}:{port} failed: {e}")
        return None


def probe_slmp(ip: str, port: int, timeout: float) -> bool:
    """SLMP 3E binary "Read Type Name" (0x0101); any 3E response (D0 00) counts"""
    payload = struct.pack("<HHH", 0x0010, 0x0101, 0x0000)          # timer, command, subcommand
    request = (
        struct.pack("<H", 0x0050)                                  # subheader "50 00"
        + struct.pack("<BBHB", 0x00, 0xFF, 0x03FF, 0x00)           # network, PC, I/O, station
        + struct.pack("<H", len(payload))
        + payload
    )
    reply = _exchange(ip, port, request, timeout, 2)
    return bool(reply) and reply[:2] == b"\xD0\x00"


def probe_modbus(ip: str, port: int, timeout: float) -> bool:
    """Modbus/TCP FC03 read of one holding register; normal or exception reply counts"""
    transaction_id = int.from_bytes(os.urandom(2), "big")
    pdu = struct.pack(">BHH", 0x03, 0, 1)
    request = struct.pack(">HHHB", transaction_id, 0, len(pdu) + 1, 1) + pdu
    reply = _exchange(ip, port, request, timeout, 8)
    if not reply or len(reply) < 8:
        return False
    tid, proto_id = struct.unpack(">HH", reply[:4])
    return tid == transaction_id and proto_id == 0 and reply[7] in (0x03, 0x83)


def probe_s7(ip: str, port: int, timeout: float) -> bool:
    """ISO-on-TCP (TPKT/COTP) connection request; COTP Connection Confirm counts"""
    cotp_cr = bytes([
        0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,   # length, CR, dst ref, src ref, class
        0xC0, 0x01, 0x0A,                           # TPDU size 1024
        0xC1, 0x02, 0x01, 0x00,                     # source TSAP
        0xC2, 0x02, 0x01, 0x02,                     # destination TSAP (rack 0, slot 2)
    ])
    request = struct.pack(">BBH", 0x03, 0x00, 4 + len(cotp_cr)) + cotp_cr
    reply = _exchange(ip, port, request, timeout, 6)
    # TPKT version 3 and COTP PDU type CC (0xD0)
    return bool(reply) and len(reply) >= 6 and reply[0] == 0x03 and (reply[5] & 0xF0) == 0xD0


def probe_ethernet_ip(ip: str, port: int, timeout: float) -> bool:
    """EtherNet/IP ListIdentity (0x0063) encapsulation request"""
    context = os.urandom(8)
    request = struct.pack("<HHII", 0x0063, 0, 0, 0) + context + struct.pack("<I", 0)
    reply = _exchange(ip, port, request, timeout, 24)
    if not reply or len(reply) < 24:
        return False
    command = struct.unpack("<H", reply[:2])[0]
    return command == 0x0063 and reply[12:20] == context


def _last_octet(address: str) -> int:
    try:
        return int(ipaddress.IPv4Address(address)) & 0xFF
    except ValueError:
        return 0


def probe_fins_udp(ip: str, port: int, timeout: float) -> bool:
    """
    FINS/UDP memory area read of DM0 (1 word); any matching FINS reply counts.
    
    Node numbers follow the same rule as FINSHandler (Omron automatic address
    conversion): DA1 = last octet of the PLC address, SA1 = last octet of
    the local address used to reach it.
    """
    sid = os.urandom(1)[0]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            request = bytes([
                0x80, 0x00, 0x02,                            # ICF, RSV, GCT
                0x00, _last_octet(ip), 0x00,                 # DNA, DA1, DA2
                0x00, _last_octet(sock.getsockname()[0]), 0x00,  # SNA, SA1, SA2
                sid,
                0x01, 0x01,                                  # memory area read
                0x82, 0x00, 0x00, 0x00,                      # DM, address 0, bit 0
                0x00, 0x01,                                  # 1 word
            ])
            sock.send(request)
            reply = sock.recv(2048)
    except OSError as e:  # timeout or ICMP port unreachable
        logger.debug(f"FINS/UDP probe {ip}:{port} failed: {e}")
        return False
    return (
        len(reply) >= 12
        and (reply[0] & 0x40) != 0
        and reply[9] == sid
        and reply[10:12] == b"\x01\x01"
    )


def probe_fins_tcp(ip: str, port: int, timeout: float) -> bool:
    """FINS/TCP node address request; a "FINS" framed reply counts"""
    request = b"FINS" + struct.pack(">III", 12, 0, 0) + struct.pack(">I", 0)
    reply = _exchange(ip, port, request, timeout, 16)
    return bool(reply) and reply[:4] == b"FINS"


PROBES: Dict[Protocol, Callable[[str, int, float], bool]] = {
    Protocol.SLMP: probe_slmp,
    Protocol.MODBUS_TCP: probe_modbus,
    Protocol.S7: probe_s7,
    Protocol.ETHERNET_IP: probe_ethernet_ip,
    Protocol.FINS: probe_fins_udp,
    Protocol.FINS_TCP: probe_fins_tcp,
}

# Protocols probed over UDP (no TCP port check beforehand)
UDP_PROTOCOLS = frozenset({Protocol.FINS})


def verify_protocol(ip: str, port: int, protocol: Protocol, timeout: float) -> bool:
    """Return True if the host answers the protocol's probe"""
    probe = PROBES.get(protocol)
    if probe is None:
        return False
    try:
        return probe(ip, port, timeout)
    except Exception as e:  # never let a probe abort discovery
        logger.debug(f"Probe {protocol.name} {ip}:{port} raised: {e}")
        return False
