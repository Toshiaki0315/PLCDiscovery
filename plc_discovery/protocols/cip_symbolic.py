"""
Symbolic tag reads over a generic CIP connection (read-only).

Controllers such as Omron NJ/NX accept the CIP Read Tag service on symbolic
paths ("Variable", "Struct.Member", "Array[3]") but are not Logix
controllers: pycomm3's LogixDriver cannot connect to them (no program-name
object / Logix tag list). This module sends Read Tag Fragmented (0x52)
through pycomm3's CIPDriver connection and decodes the atomic CIP types.

Only reads are implemented; there is no write service here.
"""

import re
import struct
from typing import Any, List, Optional, Tuple

from ..config import StatusCode

# Read Tag Fragmented: like Read Tag, plus a byte offset for replies larger
# than one packet (status 0x06 "partial transfer" means more data follows)
SERVICE_READ_TAG_FRAGMENTED = 0x52
STATUS_OK = 0x00
STATUS_PARTIAL = 0x06

# Atomic CIP data types: code -> (name, struct format, size)
CIP_ATOMIC_TYPES = {
    0xC1: ("BOOL", "<B", 1),
    0xC2: ("SINT", "<b", 1),
    0xC3: ("INT", "<h", 2),
    0xC4: ("DINT", "<i", 4),
    0xC5: ("LINT", "<q", 8),
    0xC6: ("USINT", "<B", 1),
    0xC7: ("UINT", "<H", 2),
    0xC8: ("UDINT", "<I", 4),
    0xC9: ("ULINT", "<Q", 8),
    0xCA: ("REAL", "<f", 4),
    0xCB: ("LREAL", "<d", 8),
    0xD1: ("BYTE", "<B", 1),
    0xD2: ("WORD", "<H", 2),
    0xD3: ("DWORD", "<I", 4),
    0xD4: ("LWORD", "<Q", 8),
}

# Abbreviated structure reply type (0xA0 0x02 + 2-byte handle): a whole
# structure without its layout. Members must be read by name instead.
STRUCTURE_TYPE = 0x02A0

# CIP general status -> data point status. Path errors mean the variable
# does not exist or is not published; they are not communication failures.
ILLEGAL_ADDRESS_STATUSES = {
    0x04,   # path segment error (malformed / unknown name)
    0x05,   # path destination unknown (no such variable)
    0x0F,   # privilege violation (variable not published / not accessible)
    0x13,   # not enough data
    0x16,   # object does not exist
    0x26,   # path size invalid
}
UNSUPPORTED_STATUSES = {
    0x08,   # service not supported
}

# Upper bound of fragment requests for one tag (a runaway reply must not
# keep the PLC busy): 1000 fragments of ~480 bytes
MAX_FRAGMENTS = 1000

_ELEMENTS_SUFFIX = re.compile(r"^(.*)\{(\d+)\}$")


class SymbolicReadError(Exception):
    """A CIP error reply (status) or an undecodable reply for one tag"""

    def __init__(self, status: StatusCode, message: str):
        super().__init__(message)
        self.status = status


def split_element_count(tag: str) -> Tuple[str, int]:
    """'Values[0]{10}' -> ('Values[0]', 10); 'Speed' -> ('Speed', 1)"""
    match = _ELEMENTS_SUFFIX.match(tag.strip())
    if match:
        return match.group(1), max(1, int(match.group(2)))
    return tag.strip(), 1


def status_for_cip_error(code: Optional[int]) -> StatusCode:
    if code in ILLEGAL_ADDRESS_STATUSES:
        return StatusCode.NG_ILLEGAL_ADDR
    if code in UNSUPPORTED_STATUSES:
        return StatusCode.NG_UNSUPPORTED
    return StatusCode.NG_COMM_ERROR


def _request_class():
    """GenericConnectedRequestPacket that sends a symbolic path (built lazily: pycomm3 is optional)"""
    from pycomm3.packets import GenericConnectedRequestPacket
    from pycomm3.packets.ethernetip import SendUnitDataRequestPacket

    class SymbolicReadRequestPacket(GenericConnectedRequestPacket):
        def __init__(self, sequence, path: bytes, request_data: bytes):
            super().__init__(sequence, SERVICE_READ_TAG_FRAGMENTED, 0, 0, request_data=request_data)
            self.symbolic_path = path

        def _setup_message(self):
            SendUnitDataRequestPacket._setup_message(self)
            self._msg += [self.service, self.symbolic_path, self.request_data]

    return SymbolicReadRequestPacket


def encode_tag_path(name: str) -> bytes:
    """Padded EPATH (with word length) of a symbolic name: Tag, Tag.Member, Tag[1], Program:P.Tag"""
    from pycomm3.packets.util import tag_request_path

    path = tag_request_path(name, {}, False)
    if path is None:
        raise SymbolicReadError(StatusCode.NG_ILLEGAL_ADDR, f"invalid tag name: {name}")
    return path


def read_symbolic(client, tag: str) -> Tuple[Any, str]:
    """
    Read one tag ("Name", "Name.Member", "Array[2]{5}") through a CIPDriver.

    Returns (value, type name); value is a list for an element count > 1.
    Raises SymbolicReadError for CIP error replies and undecodable data;
    transport failures propagate as pycomm3 CommError (the caller reconnects).
    """
    from pycomm3.cip_driver import with_forward_open

    name, elements = split_element_count(tag)
    path = encode_tag_path(name)
    with_forward_open(lambda _: None)(client)        # connected messaging
    request_class = _request_class()

    type_code: Optional[int] = None
    payload = b""
    for _ in range(MAX_FRAGMENTS):
        data = struct.pack("<HI", elements, len(payload))
        response = client.send(request_class(client._sequence, path, data))
        status = getattr(response, "service_status", None)
        if status not in (STATUS_OK, STATUS_PARTIAL):
            if status is None:
                # No CIP reply at all (session / connection problem)
                from pycomm3.exceptions import CommError
                raise CommError(response.error or "no reply")
            raise SymbolicReadError(status_for_cip_error(status),
                                    f"{tag}: CIP status 0x{status:02X} ({response.error})")
        reply = response.data or b""
        if len(reply) < 2:
            raise SymbolicReadError(StatusCode.NG_COMM_ERROR, f"{tag}: short reply")
        code = struct.unpack("<H", reply[:2])[0]
        header = 4 if code == STRUCTURE_TYPE else 2
        if type_code is None:
            type_code = code
        payload += reply[header:]
        if status == STATUS_OK:
            break
        if len(reply) <= header:
            raise SymbolicReadError(StatusCode.NG_COMM_ERROR, f"{tag}: empty partial reply")
    else:
        raise SymbolicReadError(StatusCode.NG_COMM_ERROR, f"{tag}: too many fragments")

    return decode_values(tag, type_code, payload, elements)


def decode_values(tag: str, type_code: int, payload: bytes, elements: int) -> Tuple[Any, str]:
    """Decode the data of a Read Tag reply (atomic types only)"""
    if type_code == STRUCTURE_TYPE:
        raise SymbolicReadError(
            StatusCode.NG_UNSUPPORTED,
            f"{tag}: structure without layout information (read its members by name)")
    if type_code not in CIP_ATOMIC_TYPES:
        raise SymbolicReadError(StatusCode.NG_UNSUPPORTED, f"{tag}: data type 0x{type_code:04X}")
    type_name, fmt, size = CIP_ATOMIC_TYPES[type_code]
    if type_name == "BOOL" and len(payload) == 2 * elements:
        fmt, size = "<H", 2             # Omron returns BOOL as a 2-byte value
    if len(payload) < size * elements:
        raise SymbolicReadError(StatusCode.NG_COMM_ERROR,
                                f"{tag}: {len(payload)} bytes for {elements} x {type_name}")
    values: List[Any] = [struct.unpack_from(fmt, payload, i * size)[0] for i in range(elements)]
    if type_name == "BOOL":
        values = [1 if v else 0 for v in values]
    return (values if elements > 1 or tag.rstrip().endswith("}") else values[0]), type_name
