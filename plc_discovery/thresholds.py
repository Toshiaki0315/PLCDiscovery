"""
Threshold monitoring for periodic scans (read-only).

A threshold is a condition on one address or tag, e.g. ``D100 > 80`` or
``Motor.Speed <= 0``. While a periodic scan runs, a THRESHOLD_EXCEEDED
notification is sent when a condition becomes true; it is sent again only
after the value has gone back inside the limit (one message per excursion,
not one per cycle).

When the value goes back inside the limit, THRESHOLD_CLEARED is sent
with how long it was outside (only for excursions that were notified).

Written in the config file::

    thresholds:
      - address: D100
        op: ">"
        value: 80
        name: Furnace temperature   # optional
        target: 192.168.1.10        # optional: only this PLC (IP or label)
        hysteresis: 2               # optional: back inside only at <= 78
        for_cycles: 3               # optional: outside 3 cycles in a row

or on the command line: ``--threshold "D100>80" --threshold "D200<=10"``
(command-line and GUI conditions apply to every target, without
hysteresis, from the first cycle).

The value compared is the converted value when a data type is applied
(FLOAT, DWORD, ...), otherwise the raw word. Addresses that were not read
successfully are skipped and keep the previous state.
"""

import math
import operator
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, NamedTuple, Optional, Set, Tuple

from .config import DataPoint, StatusCode

OPERATORS: Dict[str, Callable[[float, float], bool]] = {
    ">": operator.gt,
    ">=": operator.ge,
    "<": operator.lt,
    "<=": operator.le,
    "==": operator.eq,
    "!=": operator.ne,
}

# "D100>80", "Motor.Speed <= 0.5", "Program:Main.Step != 3"
_CONDITION = re.compile(r"^\s*(?P<address>[^<>=!]+?)\s*(?P<op>>=|<=|==|!=|>|<)\s*(?P<value>[^<>=!]+?)\s*$")


@dataclass(frozen=True)
class Threshold:
    address: str
    op: str
    value: float
    name: Optional[str] = None
    # Only this target (its IP or its label); None: every target
    target: Optional[str] = None
    # Back inside only once the value is this far inside the limit (> / >= / < / <=)
    hysteresis: float = 0.0
    # Consecutive read cycles outside the limit before it counts as exceeded
    for_cycles: int = 1

    @property
    def condition(self) -> str:
        return f"{self.address} {self.op} {self.value:g}"

    @property
    def label(self) -> str:
        return f"{self.name} ({self.condition})" if self.name else self.condition

    def matches(self, address: str) -> bool:
        # Device addresses and CIP tag names are case-insensitive
        return address.casefold() == self.address.casefold()

    def applies_to(self, target: str, plc_ip: Optional[str] = None) -> bool:
        """Whether this threshold is watched on the target (label or IP)"""
        if self.target is None:
            return True
        wanted = self.target.casefold()
        return wanted == target.casefold() or (plc_ip is not None and wanted == plc_ip.casefold())

    def exceeded(self, value: float) -> bool:
        return OPERATORS[self.op](value, self.value)

    def back_inside(self, value: float) -> bool:
        """Whether an exceeded value has returned inside (past the hysteresis)"""
        if self.op in (">", ">="):
            return not OPERATORS[self.op](value, self.value - self.hysteresis)
        if self.op in ("<", "<="):
            return not OPERATORS[self.op](value, self.value + self.hysteresis)
        return not self.exceeded(value)


def _number(value: Any, where: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{where}: value must be a number, got {value!r}")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{where}: value must be a number, got {value!r}") from None
    if not math.isfinite(number):
        raise ValueError(f"{where}: value must be a finite number, got {value!r}")
    return number


def parse_threshold(text: str) -> Threshold:
    """'D100>80' -> Threshold('D100', '>', 80.0); ValueError when malformed"""
    match = _CONDITION.match(text or "")
    if not match:
        raise ValueError(
            f"invalid threshold {text!r} (expected ADDRESS OP VALUE with OP one of {', '.join(OPERATORS)}, "
            'e.g. "D100>80")'
        )
    return Threshold(match["address"], match["op"], _number(match["value"], f"threshold {text!r}"))


# Keys of a thresholds: entry in the config file
THRESHOLD_KEYS = ("address", "op", "value", "name", "target", "hysteresis", "for_cycles")


def threshold_from_dict(item: Any, where: str = "threshold") -> Threshold:
    """A config file entry {address, op, value, name?}; ValueError when invalid"""
    if not isinstance(item, dict):
        raise ValueError(f"{where} must be a mapping with address, op and value")
    # A misspelt key (e.g. "tagret") would otherwise silently fall back to
    # the default: a threshold meant for one PLC watched on every PLC
    unknown = sorted(str(k) for k in item if k not in THRESHOLD_KEYS)
    if unknown:
        raise ValueError(f"{where}: unknown key(s) {', '.join(unknown)} (allowed: {', '.join(THRESHOLD_KEYS)})")
    address = str(item.get("address") or "").strip()
    if not address:
        raise ValueError(f"{where}.address is required")
    op = str(item.get("op", "")).strip()
    if op not in OPERATORS:
        raise ValueError(f"{where}.op: unknown operator {item.get('op')!r} (allowed: {', '.join(OPERATORS)})")
    if "value" not in item:
        raise ValueError(f"{where}.value is required")
    name = item.get("name")
    target = item.get("target")
    if target is not None and not (isinstance(target, str) and target.strip()):
        raise ValueError(f"{where}.target must be an IP address or target label, got {target!r}")
    hysteresis = _number(item.get("hysteresis", 0), f"{where}.hysteresis")
    if hysteresis < 0:
        raise ValueError(f"{where}.hysteresis must be 0 or more, got {item.get('hysteresis')!r}")
    if hysteresis and op in ("==", "!="):
        raise ValueError(f"{where}.hysteresis cannot be used with {op}")
    for_cycles = item.get("for_cycles", 1)
    if isinstance(for_cycles, bool) or not isinstance(for_cycles, int) or for_cycles < 1:
        raise ValueError(f"{where}.for_cycles must be a whole number of 1 or more, got {for_cycles!r}")
    return Threshold(
        address,
        op,
        _number(item["value"], where),
        str(name) if name else None,
        target=target.strip() if target else None,
        hysteresis=hysteresis,
        for_cycles=for_cycles,
    )


def parse_thresholds(texts: Iterable[str]) -> List[Threshold]:
    """CLI / GUI conditions; each text may hold several, separated by commas"""
    return [parse_threshold(part) for text in texts for part in str(text).split(",") if part.strip()]


def numeric_value(point: DataPoint) -> Optional[float]:
    """
    The number to compare: the converted value when the point went through
    data type conversion, else the raw value.

    A converted point never falls back to its raw word: an incomplete
    multi-word value (one of its words failed), the later words of a value,
    NaN / infinity and text have no comparable number, and the raw 16-bit
    word of e.g. a FLOAT is unrelated to the value the limit was set for.
    """
    if point.status != StatusCode.OK:
        return None
    converted = point.data_type is not None or point.converted_value is not None
    value = point.converted_value if converted else point.value
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)) and math.isfinite(value):
        return float(value)
    return None


class ThresholdEvent(NamedTuple):
    threshold: Threshold
    value: float
    # Back inside: seconds the value was outside the limit
    duration: float = 0.0


class ThresholdCheck(NamedTuple):
    """What one cycle changed, see ThresholdMonitor.evaluate"""

    crossed: List[ThresholdEvent]  # went outside the limit (log)
    returned: List[ThresholdEvent]  # came back inside (log)
    exceeded: List[ThresholdEvent]  # excursions to notify now
    cleared: List[ThresholdEvent]  # notified excursions now over, to notify


# may_notify(threshold, kind): kind is "exceeded" or "cleared"
MayNotify = Callable[[Threshold, str], bool]


class ThresholdMonitor:
    """Per target, which thresholds are exceeded and what has been notified"""

    def __init__(self, thresholds: Iterable[Threshold]):
        self.thresholds = list(thresholds)
        Key = Tuple[str, Threshold]
        # Excursions in progress, with the time the value first went outside
        self._exceeded: Dict[Key, float] = {}
        # Consecutive cycles outside the limit, not yet for_cycles long
        self._pending: Dict[Key, Tuple[int, float]] = {}
        # Excursions the receiver was told about (exceeded, not yet cleared)
        self._notified: Set[Key] = set()
        # Notified excursions that ended but whose clear is not sent yet
        self._unsent_clear: Dict[Key, ThresholdEvent] = {}

    def __bool__(self) -> bool:
        return bool(self.thresholds)

    def for_target(self, target: str, plc_ip: Optional[str] = None) -> List[Threshold]:
        return [t for t in self.thresholds if t.applies_to(target, plc_ip)]

    def evaluate(
        self,
        target: str,
        points: Iterable[DataPoint],
        may_notify: Optional[MayNotify] = None,
        plc_ip: Optional[str] = None,
        now: float = 0.0,
    ) -> ThresholdCheck:
        """
        Update the state with this cycle's points (read at loop time ``now``).

        A value counts as exceeded after ``for_cycles`` read cycles in a row
        outside the limit, and as back inside once it is ``hysteresis``
        inside it. The receiver is kept in line with that state: an
        excursion is notified once, and its end is notified if it was.
        While ``may_notify`` is False for a notification (it would be
        throttled) it stays unsent and is offered again on later cycles; an
        excursion that ends before it could be notified is never notified.
        """
        result = ThresholdCheck([], [], [], [])
        by_address = {p.address.casefold(): p for p in points}
        for threshold in self.for_target(target, plc_ip):
            point = by_address.get(threshold.address.casefold())
            value = numeric_value(point) if point is not None else None
            if value is None:
                continue  # not read this cycle: keep the previous state
            key = (target, threshold)
            if key in self._exceeded:
                if threshold.back_inside(value):
                    event = ThresholdEvent(threshold, value, now - self._exceeded.pop(key))
                    result.returned.append(event)
                    if key in self._notified:
                        self._unsent_clear[key] = event
            elif threshold.exceeded(value):
                count, since = self._pending.get(key, (0, now))
                if count + 1 >= threshold.for_cycles:
                    self._pending.pop(key, None)
                    self._exceeded[key] = since
                    result.crossed.append(ThresholdEvent(threshold, value))
                else:
                    self._pending[key] = (count + 1, since)
            else:
                self._pending.pop(key, None)

            # Bring the receiver in line with the state
            if key in self._exceeded:
                # Outside again before the clear went out: still what it was told
                self._unsent_clear.pop(key, None)
                if key not in self._notified and (may_notify is None or may_notify(threshold, "exceeded")):
                    self._notified.add(key)
                    result.exceeded.append(ThresholdEvent(threshold, value))
            elif key in self._notified and (may_notify is None or may_notify(threshold, "cleared")):
                self._notified.discard(key)
                result.cleared.append(self._unsent_clear.pop(key, ThresholdEvent(threshold, value)))
        return result

    def delivery_failed(self, target: str, event: ThresholdEvent, kind: str) -> None:
        """
        A notification handed out by evaluate() could not be delivered
        (``kind``: "exceeded" or "cleared"): put it back so it is offered
        again on a later cycle instead of leaving the receiver out of date.
        """
        key = (target, event.threshold)
        if kind == "cleared":
            self._notified.add(key)
            self._unsent_clear.setdefault(key, event)
        else:
            self._notified.discard(key)

    def check(
        self,
        target: str,
        points: Iterable[DataPoint],
        may_notify: Optional[MayNotify] = None,
    ) -> List[Tuple[Threshold, float]]:
        """The excursions to notify this cycle (see evaluate)"""
        return [(e.threshold, e.value) for e in self.evaluate(target, points, may_notify).exceeded]

    def unmatched(self, points: Iterable[DataPoint], target: str = "", plc_ip: Optional[str] = None) -> List[Threshold]:
        """The target's thresholds whose address is not among the points at all (not read)"""
        addresses = {p.address.casefold() for p in points}
        thresholds = self.for_target(target, plc_ip) if target else self.thresholds
        return [t for t in thresholds if t.address.casefold() not in addresses]

    def unknown_targets(self, names: Iterable[str]) -> List[Threshold]:
        """Thresholds limited to a target that is none of these labels / IPs"""
        known = {n.casefold() for n in names}
        return [t for t in self.thresholds if t.target is not None and t.target.casefold() not in known]
