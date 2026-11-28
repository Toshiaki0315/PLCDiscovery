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
import time
from typing import Callable, Dict, Optional

from .config import Protocol, clean_device_text

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


# SLMP communication settings tried by identify_slmp(), in this order:
# (frame, ascii). The PLC answers only the frame and data code its port is
# configured for (GX Works "交信データコード": binary or ASCII).
SLMP_SETTINGS = (("3E", False), ("4E", False), ("3E", True), ("4E", True))

# Read CPU Model Name answer: 16 characters of model name, then the model code
SLMP_MODEL_NAME_SIZE = 16


def slmp_type_name_request(frame: str, ascii_code: bool) -> bytes:
    """SLMP "Read CPU Model Name" (0101) request to the connected station"""
    timer, command, subcommand = 0x0010, 0x0101, 0x0000
    if ascii_code:
        body = f"{timer:04X}{command:04X}{subcommand:04X}"
        route = "00FF03FF00"  # network, PC, I/O (big-endian text), station
        text_head = "5000" if frame == "3E" else ("5400" + "0000" + "0000")  # 4E: serial, 0000
        return (text_head + route + f"{len(body):04X}" + body).encode("ascii")
    payload = struct.pack("<HHH", timer, command, subcommand)
    head = struct.pack("<H", 0x0050) if frame == "3E" else struct.pack("<HHH", 0x0054, 0x0000, 0x0000)
    return head + struct.pack("<BBHB", 0x00, 0xFF, 0x03FF, 0x00) + struct.pack("<H", len(payload)) + payload


def parse_slmp_type_name(reply: bytes, frame: str, ascii_code: bool) -> Optional[dict]:
    """
    Settings and model of an answer to slmp_type_name_request().

    Any answer in the frame's format counts, an error end code included
    (e.g. a Keyence KV or a module that does not support 0101): the
    protocol and its settings are confirmed, only the model is then unknown.
    """
    if ascii_code:
        header = 18 if frame == "3E" else 26
        subheader = b"D000" if frame == "3E" else b"D400"
        if len(reply) < header + 4 or reply[:4].upper() != subheader:
            return None
        try:
            end_code = int(reply[header : header + 4].decode("ascii"), 16)
        except ValueError:
            return None
        data = reply[header + 4 :]
        name = data[:SLMP_MODEL_NAME_SIZE]
        code_text = data[SLMP_MODEL_NAME_SIZE : SLMP_MODEL_NAME_SIZE + 4]
        try:
            code: Optional[int] = int(code_text.decode("ascii"), 16) if len(code_text) == 4 else None
        except ValueError:
            code = None
    else:
        header = 9 if frame == "3E" else 13
        subheader = b"\xd0\x00" if frame == "3E" else b"\xd4\x00"
        if len(reply) < header + 2 or reply[:2] != subheader:
            return None
        end_code = struct.unpack("<H", reply[header : header + 2])[0]
        data = reply[header + 2 :]
        name = data[:SLMP_MODEL_NAME_SIZE]
        code_bytes = data[SLMP_MODEL_NAME_SIZE : SLMP_MODEL_NAME_SIZE + 2]
        code = struct.unpack("<H", code_bytes)[0] if len(code_bytes) == 2 else None
    model = None
    if end_code == 0 and len(name) == SLMP_MODEL_NAME_SIZE:
        model = clean_device_text(name.decode("ascii", errors="replace").strip(" \x00")) or None
    return {
        "frame": frame,
        "ascii": ascii_code,
        "end_code": end_code,
        "model": model,
        "model_code": code if model else None,
    }


def identify_slmp(
    ip: str, port: int, timeout: float, interval: float = 0.0, report: Optional[dict] = None
) -> Optional[dict]:
    """
    Find the frame and data code a port answers SLMP with, and the CPU model.

    Tries SLMP_SETTINGS one after another (one connection each, ``interval``
    seconds apart) until one is answered. An open port that answers none
    costs one timeout per setting; a port that cannot be connected to ends
    the search at once.

    ``report`` (when given) gets "closed": True when the device closed every
    connection without answering - typically a PLC whose connections are
    all in use (a gateway or a GOT already connected), not a device that
    speaks another protocol - and "reacted": True when it replied anything
    or closed a connection (a device that stays silent is not a TLS
    service: see speaks_tls).

    Returns:
        {"frame": "3E"/"4E", "ascii": bool, "end_code": int,
         "model": str or None, "model_code": int or None}, or None
    """

    closed = []
    for i, (frame, ascii_code) in enumerate(SLMP_SETTINGS):
        if i and interval:
            time.sleep(interval)
        state: dict = {}
        reply = _exchange_slmp(ip, port, slmp_type_name_request(frame, ascii_code), timeout, frame, ascii_code, state)
        if reply is None:
            return None  # no connection: the other settings cannot be answered either
        # Any reply, even one that is not SLMP, means the device talked:
        # not a PLC whose connections are all in use
        closed.append(not reply and bool(state.get("closed")))
        if report is not None:
            report["closed"] = all(closed)
            # The device reacted at all (any reply, or a close): a TLS
            # server does so at once, on the first byte of an SLMP request
            report["reacted"] = report.get("reacted", False) or bool(reply) or bool(state.get("closed"))
        if not reply:
            continue  # connected, not answered in this setting
        identity = parse_slmp_type_name(reply, frame, ascii_code)
        if identity:
            return identity
    return None


def _exchange_slmp(
    ip: str, port: int, request: bytes, timeout: float, frame: str, ascii_code: bool, state: Optional[dict] = None
) -> Optional[bytes]:
    """
    Send one SLMP request and read one whole answer: the header, then as
    many bytes as its data length field gives (an error answer is shorter
    than a model name answer and must not cost a timeout). Whatever arrived
    before a timeout or a close is returned (b"" if nothing did); None when
    the connection could not be made. ``state["closed"]`` tells that the
    device closed (or reset) the connection before answering anything.
    """
    if ascii_code:
        header_size = 18 if frame == "3E" else 26
        length_at, length_size = header_size - 4, 4
    else:
        header_size = 9 if frame == "3E" else 13
        length_at, length_size = header_size - 2, 2
    data = b""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError as e:
        logger.debug(f"SLMP probe {ip}:{port}: {e}")
        return None
    try:
        with sock:
            sock.settimeout(timeout)
            sock.sendall(request)
            total = None
            while total is None or len(data) < total:
                chunk = sock.recv(512)
                if not chunk:
                    if not data and state is not None:
                        state["closed"] = True
                    break
                data += chunk
                if total is None and len(data) >= header_size:
                    field = data[length_at : length_at + length_size]
                    try:
                        length = int(field.decode("ascii"), 16) if ascii_code else int.from_bytes(field, "little")
                    except ValueError:
                        break  # not an SLMP answer in this setting
                    total = header_size + length
    except socket.timeout as e:
        logger.debug(f"SLMP probe {ip}:{port} ({frame}{' ASCII' if ascii_code else ''}): {e}")
    except OSError as e:  # reset by the device
        if not data and state is not None:
            state["closed"] = True
        logger.debug(f"SLMP probe {ip}:{port} ({frame}{' ASCII' if ascii_code else ''}): {e}")
    return data


def identify_slmp_udp(ip: str, port: int, timeout: float, interval: float = 0.0) -> Optional[dict]:
    """
    identify_slmp() for a port opened for UDP.

    UDP has no connection to check first, so every host costs a wait: the
    four settings are sent one after another (``interval`` apart) on one
    socket and the first answer is taken, which keeps a silent host at about
    one timeout. The PLC answers only the setting its port is set to.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as e:
        logger.debug(f"SLMP/UDP probe {ip}:{port}: {e}")
        return None
    with sock:
        try:
            sock.connect((ip, port))  # answers from other hosts are not taken
            for i, (frame, ascii_code) in enumerate(SLMP_SETTINGS):
                if i and interval:
                    time.sleep(interval)
                sock.send(slmp_type_name_request(frame, ascii_code))
            deadline = time.monotonic() + timeout
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    return None
                sock.settimeout(left)
                reply = sock.recv(4096)
                for frame, ascii_code in SLMP_SETTINGS:
                    identity = parse_slmp_type_name(reply, frame, ascii_code)
                    if identity:
                        return identity
        except OSError as e:  # timeout, or nothing listening there (ICMP port unreachable)
            logger.debug(f"SLMP/UDP probe {ip}:{port}: {e}")
            return None


def probe_slmp_udp(ip: str, port: int, timeout: float) -> bool:
    """SLMP "Read CPU Model Name" over UDP in any frame / data code"""
    return identify_slmp_udp(ip, port, timeout) is not None


def speaks_tls(ip: str, port: int, timeout: float) -> bool:
    """
    Whether a port completes a TLS handshake (HTTPS and the like).

    Used for an SLMP port that did not answer SLMP but reacted at once
    (identify_slmp report "reacted": some reply, or a close): a TLS server
    does that with any data that is not TLS - an alert (OpenSSL) or a close,
    the latter just like a PLC whose connections are all in use - but only
    the TLS server then accepts a handshake (e.g. a Synology NAS, whose
    HTTPS port is 5001 as well). A port that stays silent is not checked.
    The certificate is not checked: only the protocol matters here.
    """
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with context.wrap_socket(sock):
                return True  # handshake completed
    except (OSError, ValueError) as e:  # ssl.SSLError is an OSError
        logger.debug(f"TLS check {ip}:{port}: {e}")
        return False


def probe_slmp(ip: str, port: int, timeout: float) -> bool:
    """SLMP "Read CPU Model Name" (0x0101) in any frame / data code; any SLMP answer counts"""
    return identify_slmp(ip, port, timeout) is not None


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
    cotp_cr = bytes(
        [
            0x11,
            0xE0,
            0x00,
            0x00,
            0x00,
            0x01,
            0x00,  # length, CR, dst ref, src ref, class
            0xC0,
            0x01,
            0x0A,  # TPDU size 1024
            0xC1,
            0x02,
            0x01,
            0x00,  # source TSAP
            0xC2,
            0x02,
            0x01,
            0x02,  # destination TSAP (rack 0, slot 2)
        ]
    )
    request = struct.pack(">BBH", 0x03, 0x00, 4 + len(cotp_cr)) + cotp_cr
    reply = _exchange(ip, port, request, timeout, 6)
    # TPKT version 3 and COTP PDU type CC (0xD0)
    return reply is not None and len(reply) >= 6 and reply[0] == 0x03 and (reply[5] & 0xF0) == 0xD0


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
            request = bytes(
                [
                    0x80,
                    0x00,
                    0x02,  # ICF, RSV, GCT
                    0x00,
                    _last_octet(ip),
                    0x00,  # DNA, DA1, DA2
                    0x00,
                    _last_octet(sock.getsockname()[0]),
                    0x00,  # SNA, SA1, SA2
                    sid,
                    0x01,
                    0x01,  # memory area read
                    0x82,
                    0x00,
                    0x00,
                    0x00,  # DM, address 0, bit 0
                    0x00,
                    0x01,  # 1 word
                ]
            )
            sock.send(request)
            reply = sock.recv(2048)
    except OSError as e:  # timeout or ICMP port unreachable
        logger.debug(f"FINS/UDP probe {ip}:{port} failed: {e}")
        return False
    return len(reply) >= 12 and (reply[0] & 0x40) != 0 and reply[9] == sid and reply[10:12] == b"\x01\x01"


def parse_eip_identity(reply: bytes) -> Optional[dict]:
    """
    Parse an EtherNet/IP ListIdentity reply (CIP identity item 0x0C).

    Returns vendor_id, device_type, product_code, revision ("major.minor"),
    serial, product_name and - when names are known to pycomm3 - vendor and
    product_type. The trailing State byte is optional (some devices and the
    bundled simulator omit it), so this is more tolerant than pycomm3.
    """
    try:
        if len(reply) < 26 or struct.unpack("<H", reply[:2])[0] != 0x0063:
            return None
        item_count = struct.unpack("<H", reply[24:26])[0]
        offset = 26
        for _ in range(item_count):
            item_type, item_len = struct.unpack("<HH", reply[offset : offset + 4])
            offset += 4
            item = reply[offset : offset + item_len]
            offset += item_len
            if item_type != 0x000C or len(item) < 2 + 16 + 15:
                continue
            body = item[2 + 16 :]  # skip protocol version and socket address
            vendor_id, device_type, product_code = struct.unpack("<HHH", body[:6])
            revision = f"{body[6]}.{body[7]}"
            serial = struct.unpack("<I", body[10:14])[0]
            name_len = body[14]
            product_name = clean_device_text(body[15 : 15 + name_len].decode("ascii", errors="replace"))
            identity = {
                "vendor_id": vendor_id,
                "device_type": device_type,
                "product_code": product_code,
                "revision": revision,
                "serial": f"{serial:08x}",
                "product_name": product_name,
            }
            try:
                from pycomm3.custom_types import PRODUCT_TYPES, VENDORS

                identity["vendor"] = VENDORS.get(vendor_id)
                identity["product_type"] = PRODUCT_TYPES.get(device_type)
            except ImportError:
                pass
            return identity
    except (struct.error, IndexError):
        return None
    return None


def read_eip_identity(ip: str, port: int, timeout: float) -> Optional[dict]:
    """Send ListIdentity over TCP and return the parsed identity (or None)"""
    context = os.urandom(8)
    request = struct.pack("<HHII", 0x0063, 0, 0, 0) + context + struct.pack("<I", 0)
    reply = _exchange(ip, port, request, timeout, 24)
    if not reply or len(reply) < 24 or reply[12:20] != context:
        return None
    length = struct.unpack("<H", reply[2:4])[0]
    # read the rest of the reply if it arrived in pieces
    if len(reply) < 24 + length:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(request)
                data = b""
                while len(data) < 24 + length:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                reply = data if data[12:20] == context else reply
        except OSError:
            pass
    return parse_eip_identity(reply)


def probe_fins_tcp(ip: str, port: int, timeout: float) -> bool:
    """FINS/TCP node address request; a "FINS" framed reply counts"""
    request = b"FINS" + struct.pack(">III", 12, 0, 0) + struct.pack(">I", 0)
    reply = _exchange(ip, port, request, timeout, 16)
    return reply is not None and reply[:4] == b"FINS"


PROBES: Dict[Protocol, Callable[[str, int, float], bool]] = {
    Protocol.SLMP: probe_slmp,
    Protocol.MODBUS_TCP: probe_modbus,
    Protocol.S7: probe_s7,
    Protocol.ETHERNET_IP: probe_ethernet_ip,
    Protocol.FINS: probe_fins_udp,
    Protocol.FINS_TCP: probe_fins_tcp,
    Protocol.SLMP_UDP: probe_slmp_udp,
}

# Protocols probed over UDP (no TCP port check beforehand)
UDP_PROTOCOLS = frozenset({Protocol.FINS, Protocol.SLMP_UDP})


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
