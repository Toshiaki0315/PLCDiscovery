"""
Symbolic tag reads over a generic CIP connection (read-only).

Controllers such as Omron NJ/NX accept the CIP Read Tag service on symbolic
paths ("Variable", "Struct.Member", "Array[3]") but are not Logix
controllers: pycomm3's LogixDriver cannot connect to them (no program-name
object / Logix tag list). This module sends Read Tag Fragmented (0x52)
through pycomm3's CIPDriver connection and decodes the atomic CIP types
and STRING. Single values are packed into Multiple Service requests (0x0A)
to save round trips.

Only reads are implemented; there is no write service here.
"""

import re
import struct
from typing import Any, List, Optional, Tuple, Union

from ..config import StatusCode

# Read Tag Fragmented: like Read Tag, plus a byte offset for replies larger
# than one packet (status 0x06 "partial transfer" means more data follows)
SERVICE_READ_TAG = 0x4C
SERVICE_READ_TAG_FRAGMENTED = 0x52
SERVICE_MULTIPLE = 0x0A
STATUS_OK = 0x00
STATUS_PARTIAL = 0x06
STATUS_EMBEDDED_ERROR = 0x1E  # Multiple Service: one or more requests failed
# Reply too large for the packet: read that tag on its own (fragmented)
REPLY_TOO_LARGE_STATUSES = {STATUS_PARTIAL, 0x11}

# Multiple Service limits: tags per request and request bytes (the reply of
# single values stays far below a 500-byte connection)
MAX_BATCH_TAGS = 20
MAX_BATCH_REQUEST_BYTES = 400

# STRING (Omron NJ/NX): 2-byte length, then the characters
CIP_STRING_TYPE = 0xD0

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
    0x04,  # path segment error (malformed / unknown name)
    0x05,  # path destination unknown (no such variable)
    0x0F,  # privilege violation (variable not published / not accessible)
    0x13,  # not enough data
    0x16,  # object does not exist
    0x26,  # path size invalid
}
UNSUPPORTED_STATUSES = {
    0x08,  # service not supported
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
    """GenericConnectedRequestPacket with a prebuilt request path (built lazily: pycomm3 is optional)"""
    from pycomm3.packets import GenericConnectedRequestPacket
    from pycomm3.packets.ethernetip import SendUnitDataRequestPacket

    class PathRequestPacket(GenericConnectedRequestPacket):
        def __init__(self, sequence: Any, service: int, path: bytes, request_data: bytes):
            super().__init__(sequence, service, 0, 0, request_data=request_data)
            self.request_epath = path

        def _setup_message(self):
            SendUnitDataRequestPacket._setup_message(self)
            self._msg += [self.service, self.request_epath, self.request_data]

    return PathRequestPacket


def _send(client: Any, service: int, path: bytes, data: bytes) -> Tuple[int, bytes, Any]:
    """Send one connected request; returns (CIP status, reply data). CommError if no CIP reply."""
    from pycomm3.cip_driver import with_forward_open

    with_forward_open(lambda _: None)(client)  # connected messaging
    response = client.send(_request_class()(client._sequence, service, path, data))
    status = getattr(response, "service_status", None)
    if status is None:
        # No CIP reply at all (session / connection problem)
        from pycomm3.exceptions import CommError

        raise CommError(getattr(response, "error", None) or "no reply")
    return status, response.data or b"", getattr(response, "error", None)


def encode_tag_path(name: str) -> bytes:
    """Padded EPATH (with word length) of a symbolic name: Tag, Tag.Member, Tag[1], Program:P.Tag"""
    from pycomm3.packets.util import tag_request_path

    try:
        path = tag_request_path(name, {}, False)
    except Exception as e:
        # e.g. "A[x]" or "A[1": pycomm3 raises ValueError on the index. A
        # malformed name concerns this tag only, never its batch or the link.
        raise SymbolicReadError(StatusCode.NG_ILLEGAL_ADDR, f"invalid tag name: {name} ({e})") from None
    if path is None:
        raise SymbolicReadError(StatusCode.NG_ILLEGAL_ADDR, f"invalid tag name: {name}")
    return bytes(path)


def read_symbolic(client: Any, tag: str) -> Tuple[Any, str]:
    """
    Read one tag ("Name", "Name.Member", "Array[2]{5}") through a CIPDriver.

    Returns (value, type name); value is a list for an element count > 1.
    Raises SymbolicReadError for CIP error replies and undecodable data;
    transport failures propagate as pycomm3 CommError (the caller reconnects).
    """
    name, elements = split_element_count(tag)
    path = encode_tag_path(name)

    type_code: Optional[int] = None
    payload = b""
    for _ in range(MAX_FRAGMENTS):
        data = struct.pack("<HI", elements, len(payload))
        status, reply, error = _send(client, SERVICE_READ_TAG_FRAGMENTED, path, data)
        if status not in (STATUS_OK, STATUS_PARTIAL):
            raise SymbolicReadError(status_for_cip_error(status), f"{tag}: CIP status 0x{status:02X} ({error})")
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


# Outcome of a batched tag that must be read on its own (reply too large,
# or the batch reply was not usable). The caller sends that read as a
# separate request after the packet interval.
READ_SINGLY = "read-singly"


def read_symbolic_batch(client: Any, tags: List[str]) -> Tuple[List[Any], bool]:
    """
    Read single values ("Name", "Name.Member", "Array[3]"; no {n} element
    count) in ONE Multiple Service request (no further requests here).

    Returns (outcomes, multiple_service_supported). Each outcome is
    (value, type), a SymbolicReadError, or READ_SINGLY for a tag the caller
    must read on its own. multiple_service_supported is False when the
    controller rejected the service: read every tag singly from then on.
    Transport failures propagate (CommError).
    """
    from pycomm3.packets.util import request_path

    paths: List[Union[bytes, SymbolicReadError]] = []
    for tag in tags:
        try:
            paths.append(encode_tag_path(split_element_count(tag)[0]))
        except SymbolicReadError as e:
            paths.append(e)
    requests = [bytes([SERVICE_READ_TAG]) + path + struct.pack("<H", 1) for path in paths if isinstance(path, bytes)]
    replies: List[Optional[bytes]] = []
    supported = True
    if requests:
        offsets, position = [], 2 + 2 * len(requests)
        for request in requests:
            offsets.append(position)
            position += len(request)
        body = struct.pack("<H", len(requests)) + b"".join(struct.pack("<H", o) for o in offsets) + b"".join(requests)
        status, data, _ = _send(client, SERVICE_MULTIPLE, request_path(0x02, 0x01), body)
        supported = status not in UNSUPPORTED_STATUSES
        replies = (
            list(_split_multiple_reply(data, len(requests))) if status in (STATUS_OK, STATUS_EMBEDDED_ERROR) else []
        )
        if len(replies) != len(requests):
            replies = [None] * len(requests)  # not understood: read one by one

    results: List[Any] = []
    reply_iter = iter(replies)
    for tag, path in zip(tags, paths):
        if not isinstance(path, bytes):
            results.append(path)
            continue
        reply = next(reply_iter)
        try:
            results.append(_decode_embedded_reply(tag, reply))
        except SymbolicReadError as e:
            results.append(e)
    return results, supported


def _split_multiple_reply(data: bytes, count: int) -> List[bytes]:
    """Embedded replies of a Multiple Service reply ([] if malformed)"""
    if len(data) < 2 or struct.unpack("<H", data[:2])[0] != count or len(data) < 2 + 2 * count:
        return []
    offsets = [struct.unpack("<H", data[2 + 2 * i : 4 + 2 * i])[0] for i in range(count)] + [len(data)]
    if any(not 0 < offsets[i] <= offsets[i + 1] <= len(data) for i in range(count)):
        return []
    return [data[offsets[i] : offsets[i + 1]] for i in range(count)]


def _decode_embedded_reply(tag: str, reply: Optional[bytes]) -> Any:
    """(value, type) of one embedded Read Tag reply, or READ_SINGLY"""
    if reply is None or len(reply) < 4:
        return READ_SINGLY
    status, extended = reply[2], reply[3]
    if status in REPLY_TOO_LARGE_STATUSES:
        return READ_SINGLY
    if status != STATUS_OK:
        raise SymbolicReadError(status_for_cip_error(status), f"{tag}: CIP status 0x{status:02X}")
    data = reply[4 + 2 * extended :]
    if len(data) < 2:
        raise SymbolicReadError(StatusCode.NG_COMM_ERROR, f"{tag}: short reply")
    code = struct.unpack("<H", data[:2])[0]
    header = 4 if code == STRUCTURE_TYPE else 2
    return decode_values(tag, code, data[header:], 1)


def decode_values(tag: str, type_code: int, payload: bytes, elements: int) -> Tuple[Any, str]:
    """Decode the data of a Read Tag reply (atomic types and STRING)"""
    if type_code == CIP_STRING_TYPE:
        if elements > 1 or len(payload) < 2:
            raise SymbolicReadError(StatusCode.NG_UNSUPPORTED, f"{tag}: STRING arrays are read one element at a time")
        length = struct.unpack("<H", payload[:2])[0]
        text = payload[2 : 2 + length].split(b"\x00")[0].decode("utf-8", errors="replace")
        return text, "STRING"
    if type_code == STRUCTURE_TYPE:
        raise SymbolicReadError(
            StatusCode.NG_UNSUPPORTED, f"{tag}: structure without layout information (read its members by name)"
        )
    if type_code not in CIP_ATOMIC_TYPES:
        raise SymbolicReadError(StatusCode.NG_UNSUPPORTED, f"{tag}: data type 0x{type_code:04X}")
    type_name, fmt, size = CIP_ATOMIC_TYPES[type_code]
    if type_name == "BOOL" and len(payload) == 2 * elements:
        fmt, size = "<H", 2  # Omron returns BOOL as a 2-byte value
    if len(payload) < size * elements:
        raise SymbolicReadError(StatusCode.NG_COMM_ERROR, f"{tag}: {len(payload)} bytes for {elements} x {type_name}")
    values: List[Any] = [struct.unpack_from(fmt, payload, i * size)[0] for i in range(elements)]
    if type_name == "BOOL":
        values = [1 if v else 0 for v in values]
    return (values if elements > 1 or tag.rstrip().endswith("}") else values[0]), type_name
