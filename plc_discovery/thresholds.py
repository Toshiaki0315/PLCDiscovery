"""
Threshold monitoring for periodic scans (read-only).

A threshold is a condition on one address or tag, e.g. ``D100 > 80`` or
``Motor.Speed <= 0``. While a periodic scan runs, a THRESHOLD_EXCEEDED
notification is sent when a condition becomes true; it is sent again only
after the value has gone back inside the limit (one message per excursion,
not one per cycle).

Written in the config file::

    thresholds:
      - address: D100
        op: ">"
        value: 80
        name: Furnace temperature   # optional

or on the command line: ``--threshold "D100>80" --threshold "D200<=10"``.

The value compared is the converted value when a data type is applied
(FLOAT, DWORD, ...), otherwise the raw word. Addresses that were not read
successfully are skipped.
"""

import math
import operator
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

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

    @property
    def condition(self) -> str:
        return f"{self.address} {self.op} {self.value:g}"

    @property
    def label(self) -> str:
        return f"{self.name} ({self.condition})" if self.name else self.condition

    def matches(self, address: str) -> bool:
        # Device addresses and CIP tag names are case-insensitive
        return address.casefold() == self.address.casefold()

    def exceeded(self, value: float) -> bool:
        return OPERATORS[self.op](value, self.value)


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


def threshold_from_dict(item: Any, where: str = "threshold") -> Threshold:
    """A config file entry {address, op, value, name?}; ValueError when invalid"""
    if not isinstance(item, dict):
        raise ValueError(f"{where} must be a mapping with address, op and value")
    address = str(item.get("address") or "").strip()
    if not address:
        raise ValueError(f"{where}.address is required")
    op = str(item.get("op", "")).strip()
    if op not in OPERATORS:
        raise ValueError(f"{where}.op: unknown operator {item.get('op')!r} (allowed: {', '.join(OPERATORS)})")
    if "value" not in item:
        raise ValueError(f"{where}.value is required")
    name = item.get("name")
    return Threshold(address, op, _number(item["value"], where), str(name) if name else None)


def parse_thresholds(texts: Iterable[str]) -> List[Threshold]:
    """CLI / GUI conditions; each text may hold several, separated by commas"""
    return [parse_threshold(part) for text in texts for part in str(text).split(",") if part.strip()]


def numeric_value(point: DataPoint) -> Optional[float]:
    """The number to compare: converted value if any, else the raw value"""
    if point.status != StatusCode.OK:
        return None
    for value in (point.converted_value, point.value):
        if isinstance(value, bool):
            return float(value)
        if isinstance(value, (int, float)) and math.isfinite(value):
            return float(value)
    return None


class ThresholdMonitor:
    """Which thresholds became exceeded in the latest cycle, per target"""

    def __init__(self, thresholds: Iterable[Threshold]):
        self.thresholds = list(thresholds)
        # (target, threshold) pairs currently outside the limit
        self._exceeded: Set[Tuple[str, Threshold]] = set()

    def __bool__(self) -> bool:
        return bool(self.thresholds)

    def check(self, target: str, points: Iterable[DataPoint]) -> List[Tuple[Threshold, float]]:
        """Thresholds newly exceeded by this cycle's points, with the value"""
        newly: List[Tuple[Threshold, float]] = []
        by_address = {p.address.casefold(): p for p in points}
        for threshold in self.thresholds:
            point = by_address.get(threshold.address.casefold())
            value = numeric_value(point) if point is not None else None
            if value is None:
                continue  # not read this cycle: keep the previous state
            key = (target, threshold)
            if threshold.exceeded(value):
                if key not in self._exceeded:
                    self._exceeded.add(key)
                    newly.append((threshold, value))
            else:
                self._exceeded.discard(key)
        return newly
