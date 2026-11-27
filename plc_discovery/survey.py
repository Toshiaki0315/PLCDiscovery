"""
Survey summary: what a scan found out about each PLC, in the form needed to
plan data collection with a gateway such as Takebishi DeviceGateway.

- readable ranges: every address of a scan, grouped into runs of
  consecutive addresses of one device with the same status
  ("D0-8191 OK", "R0-32767 NG_ILLEGAL_ADDR")
- per target: the device, its protocol settings, the counts per status, the
  ranges that could be read, and the PLC's response times (how long a
  collection cycle of the same reads takes at least)
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .config import DataPoint, DeviceType, PLCInfo, StatusCode

# "D100", "ZR32767": a device of the tool, then the number. Anything else (a
# tag name such as "Motor1", "ALL") is kept as it is, one run per run of
# equal status.
_ADDRESS = re.compile(r"^([A-Z]+)(\d+)$")
_DEVICES = frozenset(device.value for device in DeviceType)

# Longest text in the readable_ranges column of the summary (the full list
# is in the readable ranges file)
MAX_READABLE_TEXT = 300


@dataclass
class AddressRun:
    """Consecutive addresses of one device with the same status"""

    device: str
    start: str
    end: str
    count: int
    status: str

    @property
    def text(self) -> str:
        """ "D0-8191", "D5", or a tag's name (tags are never joined)"""
        if not self.device:
            return self.start
        if self.start == self.end:
            return f"{self.device}{self.start}"
        return f"{self.device}{self.start}-{self.end}"


def address_runs(points: Iterable[DataPoint]) -> List[AddressRun]:
    """
    The points as runs of consecutive addresses with the same status, in
    the order read. Numbered device addresses join when the number is one
    higher. Tags (DataPoint.is_tag) and anything else that is not a device
    address of the tool get a row each: a tag named "D0" is not device D0,
    and joining tags hid the names between the first and the last.
    """
    runs: List[AddressRun] = []
    last_number: Optional[int] = None
    for point in points:
        status = point.status.value
        match = None if point.is_tag else _ADDRESS.match(point.address or "")
        if match and match.group(1) in _DEVICES:
            device, number = match.group(1), int(match.group(2))
        else:
            device, number = "", None  # a tag: its name as read
        run = runs[-1] if runs else None
        if (
            run is not None
            and number is not None
            and run.status == status
            and run.device == device
            and last_number is not None
            and number == last_number + 1
        ):
            run.end = str(number) if number is not None else point.address
            run.count += 1
        else:
            start = str(number) if number is not None else point.address
            runs.append(AddressRun(device, start, start, 1, status))
        last_number = number
    return runs


def readable_text(runs: Sequence[AddressRun], limit: int = MAX_READABLE_TEXT) -> str:
    """The runs that were read (OK), e.g. "D0-8191, M0-8191", shortened to ``limit``"""
    text = ""
    ok = [run for run in runs if run.status == StatusCode.OK.value]
    for i, run in enumerate(ok):
        part = (", " if text else "") + run.text
        if len(text) + len(part) > limit:
            return text + f", … (+{len(ok) - i})"
        text += part
    return text


def summary_row(
    label: str, plc: Optional[PLCInfo], points: Sequence[DataPoint], statistics: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """One row of the scan summary for a target"""
    statistics = statistics or {}
    counts = {status: 0 for status in StatusCode}
    for point in points:
        counts[point.status] += 1
    total = len(points)
    ok = counts[StatusCode.OK]
    plc = plc or PLCInfo(ip_address=label)
    return {
        "target": label,
        "ip_address": plc.ip_address,
        "manufacturer": plc.manufacturer or "",
        "model": plc.model or "",
        "protocol": plc.protocol_label or "",
        "port": plc.port or "",
        "note": plc.note or "",
        "total_points": total,
        "ok": ok,
        "ng_illegal_addr": counts[StatusCode.NG_ILLEGAL_ADDR],
        "ng_timeout": counts[StatusCode.NG_TIMEOUT],
        "ng_comm_error": counts[StatusCode.NG_COMM_ERROR],
        "ng_unsupported": counts[StatusCode.NG_UNSUPPORTED],
        "success_rate": f"{ok / total * 100:.1f}%" if total else "N/A",
        "readable_ranges": readable_text(address_runs(points)),
        "requests": _blank(statistics.get("requests")),
        "avg_response_ms": _blank(statistics.get("avg_response_ms")),
        "max_response_ms": _blank(statistics.get("max_response_ms")),
        "scan_seconds": _blank(statistics.get("scan_seconds")),
    }


def _blank(value: Any) -> Any:
    return "" if value is None else value


SUMMARY_HEADERS = [
    "target",
    "ip_address",
    "manufacturer",
    "model",
    "protocol",
    "port",
    "note",
    "total_points",
    "ok",
    "ng_illegal_addr",
    "ng_timeout",
    "ng_comm_error",
    "ng_unsupported",
    "success_rate",
    "readable_ranges",
    "requests",
    "avg_response_ms",
    "max_response_ms",
    "scan_seconds",
]

RANGES_HEADERS = ["target", "device", "start", "end", "count", "status"]
