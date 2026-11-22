"""
Start, stop and edit the protocol simulators from one process (used by the
simulator GUI, simulator_gui.py; no Tk here, so it is testable headless).

SimulatorController runs an asyncio event loop in a background thread.
Every simulator is started there on its own host / port, and the values in
its memory can be read, written or changed automatically (sine, ramp,
random) while scanners read them, e.g. to try thresholds and hysteresis.

Areas and addresses follow what plc_scanner.py reads:
- SLMP: D, W, R, ZR, SD (words), M, X, Y, B, L, SM (bits); address = device number
- Modbus/TCP: HR, IR (words), COIL, DI (bits)
- EtherNet/IP SLC: N7 (words)
- EtherNet/IP Logix / Omron: TAG; address = tag name (numeric scalar tags)
- S7: DB1, M; address = word index (byte offset = address * 2, big-endian)
- FINS: DM, HR, W (words)
"""

import asyncio
import logging
import math
import random
import threading
from concurrent.futures import Future
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

try:
    from .common import parse_denied_ranges
    from .ethernet_ip_simulator import EtherNetIPDevice, EtherNetIPProtocol
    from .fins_simulator import FINSSimulator, FINSTCPServerProtocol, FINSUDPServerProtocol
    from .modbus_simulator import ModbusDevice, ModbusProtocol
    from .s7_simulator import COTPProtocol, S7Device
    from .slmp_simulator import SLMPDevice, SLMPProtocol
except ImportError:
    from common import parse_denied_ranges  # type: ignore[no-redef]
    from ethernet_ip_simulator import EtherNetIPDevice, EtherNetIPProtocol  # type: ignore[no-redef]
    from fins_simulator import FINSSimulator, FINSTCPServerProtocol, FINSUDPServerProtocol  # type: ignore[no-redef]
    from modbus_simulator import ModbusDevice, ModbusProtocol  # type: ignore[no-redef]
    from s7_simulator import COTPProtocol, S7Device  # type: ignore[no-redef]
    from slmp_simulator import SLMPDevice, SLMPProtocol  # type: ignore[no-redef]

logger = logging.getLogger("Simulator-Control")

Address = Union[int, str]

# Areas holding single bits (written as 0 / 1)
BIT_AREAS = {"M", "X", "Y", "B", "L", "SM", "COIL", "DI"}

WAVEFORMS = ("sine", "ramp", "random")
WAVEFORM_LABELS = {"sine": "サイン波", "ramp": "のこぎり波", "random": "ランダム"}


@dataclass(frozen=True)
class SimulatorKind:
    key: str
    title: str
    port: int
    # Default denied ranges ("5000-5100,7000-7050"); None: not configurable
    denied: Optional[str]
    areas: Tuple[str, ...]
    # plc_scanner.py arguments reading this simulator ({host} / {port})
    scanner_args: str


KINDS: Tuple[SimulatorKind, ...] = (
    SimulatorKind(
        "slmp",
        "SLMP（三菱・キーエンス）",
        5001,
        "5000-5100,7000-7050",
        ("D", "W", "R", "ZR", "SD", "M", "X", "Y", "B", "L", "SM"),
        "--mode range --target {host} --protocol slmp --port {port} --device D --range 0-99",
    ),
    SimulatorKind(
        "modbus",
        "Modbus/TCP",
        1502,
        "5000-5100,8000-8050",
        ("HR", "IR", "COIL", "DI"),
        "--mode range --target {host} --protocol modbus --port {port} --device HR --range 0-99",
    ),
    SimulatorKind(
        "eip",
        "EtherNet/IP（SLC 形式）",
        44818,
        "100-150",
        ("N7",),
        "--mode range --target {host} --protocol eip --port {port} --device D --range 0-99",
    ),
    SimulatorKind(
        "logix",
        "EtherNet/IP（Logix 形式：タグ）",
        44819,
        None,
        ("TAG",),
        "--mode range --target {host} --protocol eip --port {port} --tags Speed,Temp",
    ),
    SimulatorKind(
        "omron",
        "EtherNet/IP（オムロン NJ/NX 形式）",
        44820,
        None,
        ("TAG",),
        "--mode range --target {host} --protocol eip --port {port} --tags Temperature,TotalCount",
    ),
    SimulatorKind(
        "s7",
        "S7（シーメンス）",
        1102,
        "500-550",
        ("DB1", "M"),
        "--mode range --target {host} --protocol s7 --port {port} --device DB --range 0-99",
    ),
    SimulatorKind(
        "fins",
        "FINS（オムロン、UDP・TCP）",
        9600,
        None,
        ("DM", "HR", "W"),
        "--mode range --target {host} --protocol fins --port {port} --device DM --range 0-99",
    ),
)

KINDS_BY_KEY: Dict[str, SimulatorKind] = {k.key: k for k in KINDS}


def scanner_command(kind: SimulatorKind, host: str, port: int) -> str:
    """The plc_scanner.py command line reading this simulator"""
    target = "127.0.0.1" if host in ("0.0.0.0", "") else host
    return "python plc_scanner.py " + kind.scanner_args.format(host=target, port=port)


# --- Memory access per simulator kind ------------------------------------


def _area_dict(kind: str, device: Any, area: str) -> Dict[int, Any]:
    areas: Dict[str, Dict[int, Any]] = {}
    if kind == "slmp":
        areas = device.memory
    elif kind == "modbus":
        areas = {
            "HR": device.holding_registers,
            "IR": device.input_registers,
            "COIL": device.coils,
            "DI": device.discrete_inputs,
        }
    elif kind == "eip":
        areas = {"N7": device.integer_file}
    elif kind == "fins":
        areas = {"DM": device._dm_area, "HR": device._hr_area, "W": device._w_area}
    if area not in areas:
        raise ValueError(f"{KINDS_BY_KEY[kind].title}: unknown area {area!r}")
    return areas[area]


def _word(value: float) -> int:
    """A 16-bit word; negative values as two's complement"""
    number = int(round(value))
    if not -0x8000 <= number <= 0xFFFF:
        raise ValueError(f"value {value:g} does not fit a 16-bit word (-32768 to 65535)")
    return number & 0xFFFF


def _tag(device: Any, name: str) -> Tuple[str, Any]:
    if name not in device.logix_tags:
        raise ValueError(f"unknown tag {name!r} (tags: {', '.join(device.logix_tags)})")
    data_type, value = device.logix_tags[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"tag {name!r} ({data_type}) is not a number and cannot be edited here")
    return data_type, value


def read_value(kind: str, device: Any, area: str, address: Address) -> float:
    """The current value of one address (tag) of a running simulator's memory"""
    if kind in ("logix", "omron"):
        return float(_tag(device, str(address))[1])
    index = int(address)
    if kind == "s7":
        block = device.data_blocks.get(1, {}) if area == "DB1" else device.merkers if area == "M" else None
        if block is None:
            raise ValueError(f"S7: unknown area {area!r}")
        return float((block.get(index * 2, 0) << 8) | block.get(index * 2 + 1, 0))
    return float(int(_area_dict(kind, device, area).get(index, 0)))


def write_value(kind: str, device: Any, area: str, address: Address, value: float) -> None:
    """Write one value into a running simulator's memory (what scanners then read)"""
    if not math.isfinite(value):
        raise ValueError("value must be a finite number")
    if kind in ("logix", "omron"):
        name = str(address)
        data_type, _ = _tag(device, name)
        new: Union[int, float]
        if data_type in ("REAL", "LREAL"):
            new = float(value)
        elif data_type == "BOOL":
            new = 1 if value else 0
        else:
            new = int(round(value))
        device.logix_tags[name] = (data_type, new)
        return
    index = int(address)
    if index < 0:
        raise ValueError("address must be 0 or more")
    if kind == "s7":
        if area == "DB1":
            block = device.data_blocks.setdefault(1, {})
        elif area == "M":
            block = device.merkers
        else:
            raise ValueError(f"S7: unknown area {area!r}")
        word = _word(value)
        block[index * 2], block[index * 2 + 1] = word >> 8, word & 0xFF
        return
    memory = _area_dict(kind, device, area)
    if area in BIT_AREAS:
        bit = 1 if value else 0
        memory[index] = bool(bit) if kind == "modbus" else bit
    else:
        memory[index] = _word(value)


def wave_value(waveform: str, low: float, high: float, period: float, elapsed: float) -> float:
    """The value of an automatic change at ``elapsed`` seconds"""
    phase = (elapsed % period) / period if period > 0 else 0.0
    if waveform == "sine":
        return low + (high - low) * (1 - math.cos(2 * math.pi * phase)) / 2
    if waveform == "ramp":
        return low + (high - low) * phase
    if waveform == "random":
        return random.uniform(low, high)
    raise ValueError(f"unknown waveform {waveform!r} (allowed: {', '.join(WAVEFORMS)})")


# --- Controller ----------------------------------------------------------


@dataclass
class _Running:
    kind: SimulatorKind
    host: str
    port: int
    device: Any
    closers: List[Callable[[], Any]]
    # Open client connections (TCP transports): closed on stop, since
    # Server.close() only stops accepting new ones
    connections: Set[Any]


def _tracked(factory: Callable[[], Any], connections: Set[Any]) -> Callable[[], Any]:
    """A protocol factory whose connections are recorded in ``connections``"""

    def make() -> Any:
        protocol = factory()
        made, lost = protocol.connection_made, protocol.connection_lost
        transport: List[Any] = []

        def connection_made(t: Any) -> None:
            transport.append(t)
            connections.add(t)
            made(t)

        def connection_lost(exc: Optional[Exception]) -> None:
            for t in transport:
                connections.discard(t)
            lost(exc)

        protocol.connection_made, protocol.connection_lost = connection_made, connection_lost
        return protocol

    return make


@dataclass(frozen=True)
class Generator:
    """An automatic change of one address"""

    kind: str
    area: str
    address: Address
    waveform: str
    low: float
    high: float
    period: float

    @property
    def label(self) -> str:
        return (
            f"{KINDS_BY_KEY[self.kind].title} {self.area} {self.address}: {WAVEFORM_LABELS[self.waveform]} "
            f"{self.low:g}〜{self.high:g}（周期 {self.period:g} 秒）"
        )


class SimulatorController:
    """
    Runs the simulators in a background event loop. Every public method may
    be called from any thread (the GUI's) and waits for the loop to finish
    the work; errors are raised to the caller.
    """

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, name="simulators", daemon=True)
        self._thread.start()
        self._running: Dict[str, _Running] = {}
        self._generators: Dict[Tuple[str, str, Address], Tuple[Generator, "asyncio.Task[None]"]] = {}

    # -- helpers --

    def _call(self, coro: Any, timeout: float = 10.0) -> Any:
        future: Future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout)

    def _device(self, key: str) -> Any:
        running = self._running.get(key)
        if running is None:
            raise ValueError(f"{KINDS_BY_KEY[key].title} is not running")
        return running.device

    # -- start / stop --

    def is_running(self, key: str) -> bool:
        return key in self._running

    def port_of(self, key: str) -> Optional[int]:
        """The port a running simulator listens on (the bound one when started on port 0)"""
        running = self._running.get(key)
        return running.port if running else None

    def start(self, key: str, host: str = "127.0.0.1", port: Optional[int] = None, denied: Optional[str] = None) -> int:
        """Start one simulator; returns the port it listens on"""
        kind = KINDS_BY_KEY[key]
        if key in self._running:
            raise ValueError(f"{kind.title} is already running")
        port = kind.port if port is None else port
        if not 0 <= port <= 65535:
            raise ValueError(f"port must be 0-65535, got {port}")
        try:
            denied_ranges = parse_denied_ranges(kind.denied if denied is None else denied)
        except ValueError:
            raise ValueError(f"invalid denied ranges {denied!r} (e.g. 5000-5100,7000-7050)") from None
        running = self._call(self._start(kind, host, port, denied_ranges))
        self._running[key] = running
        logger.info(f"{kind.title} started on {host}:{running.port}")
        return int(running.port)

    async def _start(self, kind: SimulatorKind, host: str, port: int, denied: List[Tuple[int, int]]) -> _Running:
        loop = asyncio.get_running_loop()
        closers: List[Callable[[], Any]] = []
        connections: Set[Any] = set()
        device: Any
        if kind.key == "fins":
            device = FINSSimulator(host, port)
            udp, _ = await loop.create_datagram_endpoint(lambda: FINSUDPServerProtocol(device), local_addr=(host, port))
            closers.append(udp.close)
            bound = udp.get_extra_info("sockname")[1]
            try:
                server = await loop.create_server(
                    _tracked(lambda: FINSTCPServerProtocol(device), connections), host, bound
                )
            except OSError:
                udp.close()
                raise
            closers.append(server.close)
            return _Running(kind, host, bound, device, closers, connections)
        factories: Dict[str, Callable[[], Any]] = {
            "slmp": lambda: SLMPDevice(denied),
            "modbus": lambda: ModbusDevice(denied),
            "eip": lambda: EtherNetIPDevice(denied),
            "logix": lambda: EtherNetIPDevice(mode="logix"),
            "omron": lambda: EtherNetIPDevice(mode="omron"),
            "s7": lambda: S7Device(denied),
        }
        protocols: Dict[str, Callable[[Any], Any]] = {
            "slmp": SLMPProtocol,
            "modbus": ModbusProtocol,
            "eip": EtherNetIPProtocol,
            "logix": EtherNetIPProtocol,
            "omron": EtherNetIPProtocol,
            "s7": COTPProtocol,
        }
        device = factories[kind.key]()
        protocol = protocols[kind.key]
        server = await loop.create_server(_tracked(lambda: protocol(device), connections), host, port)
        closers.append(server.close)
        return _Running(kind, host, server.sockets[0].getsockname()[1], device, closers, connections)

    def stop(self, key: str) -> None:
        """Stop one simulator and its automatic changes (no-op when stopped)"""
        running = self._running.pop(key, None)
        if running is None:
            return
        for gen_key in [k for k in self._generators if k[0] == key]:
            self.stop_generator(*gen_key)

        async def close() -> None:
            for closer in running.closers:
                closer()
            # Connected scanners must see the PLC go away (e.g. to try
            # outage notifications), not keep being answered
            for transport in list(running.connections):
                transport.abort()

        self._call(close())
        logger.info(f"{running.kind.title} stopped")

    def stop_all(self) -> None:
        for key in list(self._running):
            self.stop(key)

    def shutdown(self) -> None:
        """Stop everything and the background loop (when the GUI closes)"""
        try:
            self.stop_all()
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=5)

    # -- values --

    def read(self, key: str, area: str, address: Address) -> float:
        device = self._device(key)

        async def get() -> float:
            return read_value(key, device, area, address)

        return float(self._call(get()))

    def write(self, key: str, area: str, address: Address, value: float) -> None:
        device = self._device(key)

        async def put() -> None:
            write_value(key, device, area, address, value)

        self._call(put())

    def tags(self, key: str) -> List[str]:
        """Numeric scalar tags of a running Logix / Omron simulator"""
        device = self._device(key)
        return [
            name
            for name, (_, value) in device.logix_tags.items()
            if isinstance(value, (int, float)) and not isinstance(value, bool)
        ]

    # -- automatic changes --

    def generators(self) -> List[Generator]:
        return [generator for generator, _ in self._generators.values()]

    def start_generator(self, generator: Generator, interval: float = 0.5) -> None:
        """Change one address automatically (replaces a change of the same address)"""
        if generator.waveform not in WAVEFORMS:
            raise ValueError(f"unknown waveform {generator.waveform!r}")
        if not (math.isfinite(generator.low) and math.isfinite(generator.high)) or generator.low > generator.high:
            raise ValueError("minimum must not be larger than maximum")
        if not (math.isfinite(generator.period) and generator.period > 0):
            raise ValueError("period must be more than 0 seconds")
        device = self._device(generator.kind)
        # A bad area / address / tag or a limit the area cannot hold (e.g. a
        # maximum over 65535 for a word) fails here, not later in the loop
        self.write(generator.kind, generator.area, generator.address, generator.high)
        self.write(generator.kind, generator.area, generator.address, generator.low)
        key = (generator.kind, generator.area, generator.address)
        self.stop_generator(*key)

        async def run() -> None:
            started = asyncio.get_running_loop().time()
            while True:
                elapsed = asyncio.get_running_loop().time() - started
                value = wave_value(generator.waveform, generator.low, generator.high, generator.period, elapsed)
                try:
                    write_value(generator.kind, device, generator.area, generator.address, value)
                except ValueError as e:
                    logger.error(f"auto change stopped: {generator.label}: {e}")
                    return
                await asyncio.sleep(interval)

        async def create() -> "asyncio.Task[None]":
            return asyncio.get_running_loop().create_task(run())

        self._generators[key] = (generator, self._call(create()))

    def stop_generator(self, kind: str, area: str, address: Address) -> None:
        entry = self._generators.pop((kind, area, address), None)
        if entry is not None:
            self._loop.call_soon_threadsafe(entry[1].cancel)

    def stop_all_generators(self) -> None:
        for key in list(self._generators):
            self.stop_generator(*key)
