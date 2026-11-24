"""
PLC Discovery Module - Network scanning and PLC detection

Supports:
- Same-segment UDP broadcast discovery
- User-specified IP range scanning
- Multi-protocol detection (SLMP, EtherNet/IP, Modbus/TCP, S7)
"""

import asyncio
import concurrent.futures
import ipaddress
from typing import Callable, Dict, List, Optional, Tuple

from .config import PROTOCOL_PORTS, NetworkConfig, PLCInfo, Protocol
from .probes import UDP_PROTOCOLS, read_eip_identity, verify_protocol
from .utils import (
    get_local_networks,
    get_manufacturer_from_mac,
    get_subnet_hosts,
    is_port_open,
    logger,
    parse_ip_range,
    read_arp_cache,
)

# Try to import optional dependencies
try:
    from scapy.all import ARP, Ether, conf, srp

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("scapy not available, ARP discovery disabled")


# Non-privileged ports used by the bundled simulators instead of 502 / 102.
# Probed only on loopback addresses (127.x), so LAN scans are unchanged.
SIMULATOR_PORTS: Dict[Protocol, List[int]] = {
    Protocol.MODBUS_TCP: [1502],
    Protocol.S7: [1102],
    Protocol.ETHERNET_IP: [44819, 44820],  # Logix / Omron NJ/NX modes of the EtherNet/IP simulator
}


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def plc_key(plc: PLCInfo) -> tuple:
    """Identity of a discovery result: one per IP, protocol and port"""
    return (plc.ip_address, plc.protocol, plc.port)


# Descriptive fields filled from a second source when the first lacks them
_MERGED_FIELDS = ("mac_address", "manufacturer", "model", "cpu_type", "firmware_version", "read_method")


def merge_discovery_results(primary: List[PLCInfo], extra: List[PLCInfo]) -> List[PLCInfo]:
    """
    Combine two discovery result lists into one entry per plc_key.

    Entries of ``primary`` (e.g. the TCP scan, which verified the protocol
    and read the device identity) are kept and only have empty fields filled
    from ``extra`` (e.g. UDP broadcast replies); entries found only in
    ``extra`` are appended.
    """
    merged: Dict[tuple, PLCInfo] = {}
    for plc in list(primary) + list(extra):
        key = plc_key(plc)
        known = merged.get(key)
        if known is None:
            merged[key] = plc
            continue
        for field in _MERGED_FIELDS:
            if not getattr(known, field, None) and getattr(plc, field, None):
                setattr(known, field, getattr(plc, field))
    return list(merged.values())


def target_labels(plcs: List[PLCInfo]) -> List[str]:
    """
    Name for each scan target, used as its key in results and reports.

    The IP address alone when it is unique; "IP (PROTOCOL:port)" when several
    targets share an IP (one PLC read over two protocols, local simulators,
    a gateway), so their results do not overwrite each other.
    """
    counts: Dict[str, int] = {}
    for plc in plcs:
        counts[plc.ip_address] = counts.get(plc.ip_address, 0) + 1
    labels = []
    for plc in plcs:
        label = plc.ip_address
        if counts[plc.ip_address] > 1:
            protocol = plc.protocol.name if plc.protocol else "UNKNOWN"
            label = f"{plc.ip_address} ({protocol}:{plc.port})"
        labels.append(label)
    # Same IP, protocol and port twice (e.g. two Modbus unit IDs behind one
    # gateway): number the repeats
    seen: Dict[str, int] = {}
    for i, label in enumerate(labels):
        seen[label] = seen.get(label, 0) + 1
        if seen[label] > 1:
            labels[i] = f"{label} #{seen[label]}"
    return labels


# Handler options that select another device behind the same IP, protocol
# and port (a Modbus unit behind a gateway, a FINS node, an S7 rack/slot)
_INSTANCE_OPTIONS = ("unit_id", "dest_node", "rack", "slot", "db_number")


def target_instances(plcs: List[PLCInfo]) -> List[Optional[str]]:
    """
    What tells targets with the same IP, protocol and port apart, for each
    target (None for a target that is alone on its IP, protocol and port).

    Their protocol and port are the same, so file names and database rows
    built from those alone would mix the targets' data. The name is made of
    the options that select the device (e.g. "unit_id2"); targets without
    such options, or with the same ones, are numbered in the order given.
    """
    groups: Dict[Tuple[str, Optional[Protocol], Optional[int]], List[int]] = {}
    for index, plc in enumerate(plcs):
        groups.setdefault((plc.ip_address, plc.protocol, plc.port), []).append(index)
    instances: List[Optional[str]] = [None] * len(plcs)
    for indexes in groups.values():
        if len(indexes) < 2:
            continue
        seen: Dict[str, int] = {}
        for index in indexes:
            options = plcs[index].options or {}
            name = "_".join(f"{key}{options[key]}" for key in _INSTANCE_OPTIONS if key in options)
            seen[name] = seen.get(name, 0) + 1
            if not name:
                name = str(seen[name])
            elif seen[name] > 1:
                name = f"{name}_{seen[name]}"
            instances[index] = name
    return instances


ARP_SKIPPED_MESSAGE = (
    "ARP scan skipped: administrator (root) rights are required for raw packets. "
    "PLC discovery continues; MAC addresses are read from the OS ARP cache instead."
)

# Host count above which a scan-duration warning is logged (larger than a /22)
LARGE_SCAN_WARNING_HOSTS = 1022

# Upper bound for the probe thread pool of a batch scan (threads mostly wait
# on sockets, so this costs little CPU)
MAX_PROBE_THREADS = 64

# Automatic (same-segment) discovery skips networks larger than this prefix
# (/22 = 1022 hosts). Control LANs are typically /24; bigger networks are
# usually office or virtual networks - scan them with an explicit IP range.
MAX_AUTO_SCAN_PREFIX = 22


# Manufacturer / model implied by a verified protocol, used when the device
# identification fails or the protocol has none. None = cannot be inferred
# (Modbus/TCP and EtherNet/IP are implemented by many vendors).
PROTOCOL_IDENTITY_DEFAULTS: Dict[Optional[Protocol], Tuple[Optional[str], Optional[str]]] = {
    Protocol.SLMP: ("三菱電機/キーエンス", "SLMP対応PLC"),
    Protocol.S7: ("シーメンス", "S7 PLC"),
    Protocol.FINS: ("オムロン", "FINS対応PLC"),
    Protocol.FINS_TCP: ("オムロン", "FINS対応PLC"),
    Protocol.MODBUS_TCP: (None, "Modbus/TCP対応機器"),
    Protocol.ETHERNET_IP: (None, "EtherNet/IP対応機器"),
}


# How the tool reads a device's data, shown in discovery results
READ_METHOD_ADDRESS = "アドレス（--device / --range）"
READ_METHOD_LOGIX = "タグ（タグ一覧あり。--tags / フルスキャン）"
READ_METHOD_NAMED = "変数名（--tags で指定）"
READ_METHOD_SLC = "データファイル（--device D=N7 / M=B3）"
OMRON_VENDOR_ID = 47


def eip_read_method(identity: Optional[dict]) -> Optional[str]:
    """
    Read method of an EtherNet/IP device from its ListIdentity reply, the
    same way EtherNetIPHandler.connect() chooses its driver: PLC-5/SLC/
    MicroLogix -> data files, Control/CompactLogix -> tags with a tag list,
    Omron NJ/NX -> variables by name. None when it cannot be told (other
    vendors: try --tags).
    """
    from .protocols.ethernet_ip import is_slc_identity

    if not identity:
        return None
    if is_slc_identity(identity):
        return READ_METHOD_SLC
    vendor = identity.get("vendor_id")
    name = str(identity.get("product_name", "")).lower()
    if vendor == 1 and "logix" in name and "micrologix" not in name:
        return READ_METHOD_LOGIX
    if vendor == OMRON_VENDOR_ID and name[:2] in ("nj", "nx", "ny"):
        return READ_METHOD_NAMED
    return None


class PLCDiscovery:
    """
    PLC Discovery Engine

    Scans network for PLCs using multiple protocols and methods.
    """

    def __init__(
        self,
        config: Optional[NetworkConfig] = None,
        protocols: Optional[List[Protocol]] = None,
        port: Optional[int] = None,
    ):
        """
        Args:
            config: Network configuration
            protocols: Protocols to probe (default: all). Restricting this
                shortens discovery, e.g. skipping the per-host FINS/UDP probe.
            port: Probe every protocol on this port instead of its standard
                port (auto-detection of a target given with a port only).
                The protocols are then tried one after another: a PLC port
                often accepts a single connection at a time.
        """
        self.config = config or NetworkConfig()
        self.protocols = list(protocols) if protocols else list(PROTOCOL_PORTS)
        self.port = port
        # Keyed by plc_key(): (ip, protocol, port) - one entry per protocol
        self.discovered_plcs: Dict[tuple, PLCInfo] = {}
        # Thread pool for blocking probes during a batch scan (see _probe_hosts)
        self._probe_executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self._progress_callback: Optional[Callable[[str, int, int], None]] = None

    def set_progress_callback(self, callback: Callable[[str, int, int], None]) -> None:
        """Set callback for progress updates: callback(message, current, total)"""
        self._progress_callback = callback

    def _report_progress(self, message: str, current: int = 0, total: int = 0) -> None:
        """Report progress to callback if set"""
        if self._progress_callback:
            self._progress_callback(message, current, total)
        else:
            logger.info(f"{message} ({current}/{total})" if total else message)

    async def discover_same_segment(self) -> List[PLCInfo]:
        """
        Discover PLCs on every network this PC is connected to.

        All IPv4 interfaces are scanned (e.g. an office LAN and a separate
        control LAN), and isolated networks without a default gateway work.
        Uses ARP for MAC discovery and protocol probes for detection.
        """
        # May start a subprocess (no netifaces): off the event loop
        networks = await asyncio.get_running_loop().run_in_executor(None, get_local_networks)
        if not networks:
            logger.warning(
                "No IPv4 network found on this PC (only loopback / link-local). "
                "Specify the PLC network with an IP range instead."
            )
            return []

        scan = []
        for ip, mask in networks:
            network = ipaddress.IPv4Interface(f"{ip}/{mask}").network
            if network.prefixlen < MAX_AUTO_SCAN_PREFIX:
                logger.warning(
                    f"Skipping {network} ({network.num_addresses - 2} hosts) in automatic discovery: "
                    f"larger than /{MAX_AUTO_SCAN_PREFIX}. Specify the PLC addresses with an IP range "
                    f"(e.g. --ip-range {network.network_address}/24) to scan it."
                )
                continue
            scan.append((ip, mask, str(network)))
        if not scan:
            return []
        logger.info(f"Starting same-segment discovery on: {', '.join(label for _, _, label in scan)}")

        for ip, netmask, label in scan:
            hosts = [h for h in get_subnet_hosts(ip, netmask) if h != ip]  # skip this PC
            self._report_progress(f"Scanning {len(hosts)} hosts in {label}", 0, len(hosts))

            mac_table = {}
            if SCAPY_AVAILABLE:
                mac_table = await self._arp_scan(ip, netmask)

            await self._probe_hosts(hosts, mac_table)

        await self._fill_macs_from_arp_cache()
        return list(self.discovered_plcs.values())

    async def discover_ip_range(self, ip_range: str) -> List[PLCInfo]:
        """
        Discover PLCs in a specified IP range.

        Args:
            ip_range: IP range in CIDR (192.168.1.0/24) or hyphen notation (192.168.1.1-255)
        """
        hosts = parse_ip_range(ip_range)
        total_hosts = len(hosts)

        if not hosts:
            logger.error(f"No valid hosts in range: {ip_range}")
            return []

        logger.info(f"Starting IP range discovery for {total_hosts} hosts")
        self._report_progress(f"Scanning {total_hosts} hosts", 0, total_hosts)

        await self._probe_hosts(hosts, {})
        await self._fill_macs_from_arp_cache()
        return list(self.discovered_plcs.values())

    async def _fill_macs_from_arp_cache(self) -> None:
        """
        Fill in missing MAC addresses (and the manufacturer from the MAC OUI)
        from the operating system's ARP cache. The protocol probes have just
        contacted every detected PLC, so PLCs on the local segment are in the
        cache; reading it needs no administrator rights (unlike the scapy
        ARP scan). Hosts behind a router never appear there.
        """
        missing = [plc for plc in self.discovered_plcs.values() if not plc.mac_address]
        if not missing:
            return
        cache = await asyncio.get_running_loop().run_in_executor(None, read_arp_cache)
        filled = 0
        for plc in missing:
            mac = cache.get(plc.ip_address)
            if mac:
                plc.mac_address = mac
                # The maker registered for the MAC is more specific than the
                # name the protocol implies ("三菱電機/キーエンス" for SLMP),
                # which was filled in before the MAC was known - as it is
                # when the ARP scan (administrator rights) supplies the MAC
                maker = get_manufacturer_from_mac(mac)
                implied = PROTOCOL_IDENTITY_DEFAULTS.get(plc.protocol, (None, None))[0]
                if maker and (not plc.manufacturer or plc.manufacturer == implied):
                    plc.manufacturer = maker
                filled += 1
        if filled:
            logger.info(f"MAC addresses of {filled} PLC(s) taken from the OS ARP cache")
        elif not cache:
            logger.info(
                "OS ARP cache is not readable or empty; MAC addresses stay blank "
                "(on recent macOS the ARP table is hidden from apps without Local Network access)"
            )

    async def _probe_hosts(self, hosts: List[str], mac_table: Dict[str, str]) -> None:
        """
        Probe hosts in batches. Coroutines are created per batch so a large
        range does not allocate (and leave unawaited) one coroutine per host.
        """
        total = len(hosts)
        batch_size = max(1, self.config.max_concurrent * 10)

        if total > LARGE_SCAN_WARNING_HOSTS:
            # Rough worst case: every host is silent; its protocols are probed
            # in parallel, a TCP check plus a probe each (~2 timeouts per
            # host), plus the packet interval kept between batches
            batches = total / batch_size
            worst_s = batches * (2 * self.config.discovery_timeout_ms + self.config.packet_interval_ms) / 1000
            logger.warning(
                f"Scanning {total} hosts may take up to ~{worst_s / 60:.0f} minutes; " f"consider a narrower --ip-range"
            )

        # Dedicated pool sized for one batch: every host probes all its
        # protocols at once (blocking socket calls that mostly wait). The
        # shared default pool (min(32, CPUs + 4) threads, ~8 on a 4-core PC)
        # made these calls queue: 5-10 s per batch of 10 silent hosts instead of ~1 s.
        checks_per_host = len(self.protocols) + sum(len(p) for p in SIMULATOR_PORTS.values())
        workers = min(MAX_PROBE_THREADS, batch_size * checks_per_host)
        self._probe_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="plc-probe"
        )
        try:
            for i in range(0, total, batch_size):
                batch = hosts[i : i + batch_size]
                results = await asyncio.gather(
                    *(self._probe_host_all(h, mac_table.get(h)) for h in batch), return_exceptions=True
                )

                for host, result in zip(batch, results):
                    if isinstance(result, list):
                        for plc in result:
                            self.discovered_plcs[plc_key(plc)] = plc
                    elif isinstance(result, BaseException):
                        # Not the same as "no PLC there": say that the host
                        # could not be checked
                        logger.warning(f"Probing {host} failed: {result!r}")

                self._report_progress("Scanning hosts", min(i + batch_size, total), total)
                # Packet interval between batches, as between data reads
                await asyncio.sleep(self.config.packet_interval_ms / 1000)
        finally:
            self._probe_executor.shutdown(wait=False)
            self._probe_executor = None

    async def _arp_scan(self, ip: str, netmask: str) -> Dict[str, str]:
        """
        Perform ARP scan to get MAC addresses.
        Returns dict mapping IP to MAC address.
        """
        if not SCAPY_AVAILABLE:
            return {}

        mac_table = {}
        try:
            # Build network string
            from ipaddress import IPv4Network

            network = IPv4Network(f"{ip}/{netmask}", strict=False)

            # Send ARP request
            conf.verb = 0  # Suppress scapy output
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))

            def sweep():
                options = {
                    "timeout": self.config.discovery_timeout_ms / 1000,
                    "verbose": False,
                    # One request per address of the network: paced like
                    # every other request, not sent as one broadcast burst
                    "inter": self.config.packet_interval_ms / 1000,
                }
                try:
                    # The interface of the network being scanned. Without
                    # it scapy sends on the default-route interface: the
                    # requests for a control LAN went out on the office LAN.
                    # (looked up for a neighbour: this PC's own address
                    # is routed through the loopback interface)
                    neighbour = next(str(host) for host in network.hosts() if str(host) != ip)
                    options["iface"] = conf.route.route(neighbour)[0]
                except Exception as e:
                    logger.debug(f"ARP scan: no interface found for {ip} ({e}); using scapy's default")
                return srp(arp_request, **options)

            # Run ARP scan with timeout
            loop = asyncio.get_running_loop()
            answered, _ = await loop.run_in_executor(None, sweep)

            for sent, received in answered:
                mac_table[received.psrc] = received.hwsrc.upper()
                logger.debug(f"ARP: {received.psrc} -> {received.hwsrc}")

        except Exception as e:
            # Raw packet access needs administrator/root rights (scapy raises
            # PermissionError or its own exception mentioning the permission).
            # That is the normal case for a non-elevated GUI/CLI, not an error.
            text = str(e).lower()
            if isinstance(e, PermissionError) or "permission" in text or "not permitted" in text:
                logger.info(ARP_SKIPPED_MESSAGE)
                logger.debug(f"ARP scan permission error: {e}")
            else:
                logger.warning(f"ARP scan failed: {e}")

        return mac_table

    def _candidate_ports(self, ip: str, protocol: Protocol) -> List[int]:
        """Ports to try for a protocol: the standard port, plus the simulator
        ports (non-privileged) when scanning this PC's loopback address"""
        if self.port:
            return [self.port]
        ports = [PROTOCOL_PORTS[protocol]]
        if _is_loopback(ip):
            ports += [p for p in SIMULATOR_PORTS.get(protocol, []) if p not in ports]
        return ports

    async def _probe_host(self, ip: str, mac: Optional[str] = None) -> Optional[PLCInfo]:
        """
        Probe a single host and return its primary PLC protocol (the first
        verified one), or None. Used to auto-detect a target's protocol.
        """
        found = await self._probe_host_all(ip, mac, first_only=True)
        return found[0] if found else None

    async def _probe_host_all(self, ip: str, mac: Optional[str] = None, first_only: bool = False) -> List[PLCInfo]:
        """
        Probe a single host for PLC protocols.

        Returns one PLCInfo per verified protocol/port (a multi-protocol PLC
        or a PC running several simulators answers more than one), in the
        order of PROTOCOL_PORTS. Empty list if no PLC protocol answers.
        """
        loop = asyncio.get_running_loop()
        timeout = self.config.discovery_timeout_ms / 1000
        candidates = [
            (protocol, port)
            for protocol in PROTOCOL_PORTS
            if protocol in self.protocols
            for port in self._candidate_ports(ip, protocol)
        ]

        # Batch scans use the dedicated pool; a single-host probe (protocol
        # auto-detection) fits in the default pool
        executor = self._probe_executor

        async def check(protocol: Protocol, port: int) -> bool:
            try:
                # TCP protocols: skip the probe if the port is closed.
                # UDP protocols (FINS) have no connection to check first.
                if protocol not in UDP_PROTOCOLS:
                    if not await loop.run_in_executor(executor, is_port_open, ip, port, timeout):
                        return False
                    # The port answered: this is a device. Keep the packet
                    # interval between the connections made to it.
                    await asyncio.sleep(self.config.packet_interval_ms / 1000)
                # An open port is not proof of a PLC (e.g. NAS on 5001):
                # require a valid protocol reply
                if await loop.run_in_executor(executor, verify_protocol, ip, port, protocol, timeout):
                    logger.debug(f"Verified {protocol.name} on {ip}:{port}")
                    return True
                logger.debug(f"Open port {ip}:{port} did not answer as {protocol.name}")
            except Exception as e:
                logger.debug(f"Port scan error {ip}:{port}: {e}")
            return False

        # All protocols of a host are probed concurrently: a silent host costs
        # about one timeout instead of one per protocol (6 s -> ~1 s by default).
        # That is at most one connection per protocol port, i.e. light load.
        if self.port:
            # One port for every protocol: one connection at a time, with the
            # packet interval in between, until a protocol answers
            detected: List[Tuple[Protocol, int]] = []
            for candidate in candidates:
                if detected and first_only:
                    break
                if candidate is not candidates[0]:
                    await asyncio.sleep(self.config.packet_interval_ms / 1000)
                if await check(*candidate):
                    detected.append(candidate)
        else:
            answers = await asyncio.gather(*(check(protocol, port) for protocol, port in candidates))
            detected = [candidate for candidate, ok in zip(candidates, answers) if ok]
        if first_only:
            detected = detected[:1]

        results = []
        for protocol, port in detected:
            plc_info = PLCInfo(
                ip_address=ip,
                mac_address=mac,
                protocol=protocol,
                port=port,
                manufacturer=get_manufacturer_from_mac(mac) if mac else None,
            )
            # Try to get detailed info using protocol-specific queries
            # (another connection to the device: after the packet interval)
            await asyncio.sleep(self.config.packet_interval_ms / 1000)
            results.append(await self._get_detailed_info(plc_info))
        return results

    async def _get_detailed_info(self, plc_info: PLCInfo) -> PLCInfo:
        """
        Get detailed PLC information using protocol-specific queries.
        """
        try:
            if plc_info.protocol == Protocol.SLMP:
                plc_info = await self._query_slmp_info(plc_info)
            elif plc_info.protocol == Protocol.ETHERNET_IP:
                plc_info = await self._query_eip_info(plc_info)
            elif plc_info.protocol == Protocol.MODBUS_TCP:
                plc_info = await self._query_modbus_info(plc_info)
            elif plc_info.protocol == Protocol.S7:
                plc_info = await self._query_s7_info(plc_info)
            elif plc_info.protocol in (Protocol.FINS, Protocol.FINS_TCP):
                plc_info = await self._query_fins_info(plc_info)
        except Exception as e:
            logger.debug(f"Failed to get detailed info for {plc_info.ip_address}: {e}")

        # The probe already verified the protocol: when the identification
        # failed (or the protocol has none), name what the protocol implies
        # instead of leaving the row blank
        manufacturer, model = PROTOCOL_IDENTITY_DEFAULTS.get(plc_info.protocol, (None, None))
        plc_info.manufacturer = plc_info.manufacturer or manufacturer
        plc_info.model = plc_info.model or model
        if plc_info.protocol != Protocol.ETHERNET_IP:
            plc_info.read_method = plc_info.read_method or READ_METHOD_ADDRESS
        return plc_info

    async def _query_slmp_info(self, plc_info: PLCInfo) -> PLCInfo:
        """
        Fill in SLMP device information.

        SLMP has no standard identification command, and probe_slmp() has
        already confirmed that the host answers SLMP. No further connection
        is opened (previously a pymcprotocol connection was made only to set
        these fixed names - an extra TCP session to the PLC with the
        library's own 2 s timeout instead of the discovery timeout).
        """
        plc_info.manufacturer = plc_info.manufacturer or "三菱電機/キーエンス"
        plc_info.model = plc_info.model or "SLMP対応PLC"
        return plc_info

    async def _query_eip_info(self, plc_info: PLCInfo) -> PLCInfo:
        """
        Query EtherNet/IP device for its Identity Object (ListIdentity).

        Uses our own tolerant parser: pycomm3's CIPDriver has no
        get_plc_info() (that was the AttributeError logged by pycomm3) and its
        list_identity() rejects replies without the optional State byte.
        """
        try:
            identity = await asyncio.get_running_loop().run_in_executor(
                None,
                read_eip_identity,
                plc_info.ip_address,
                plc_info.port or 44818,
                self.config.discovery_timeout_ms / 1000,
            )
        except Exception as e:
            logger.debug(f"EtherNet/IP identity query failed: {e}")
            return plc_info
        if identity:
            plc_info.manufacturer = identity.get("vendor") or plc_info.manufacturer or f"Vendor {identity['vendor_id']}"
            plc_info.model = identity.get("product_name") or plc_info.model
            plc_info.firmware_version = identity.get("revision") or plc_info.firmware_version
            plc_info.read_method = eip_read_method(identity) or plc_info.read_method
        return plc_info

    async def _query_modbus_info(self, plc_info: PLCInfo) -> PLCInfo:
        """Query Modbus device for identification"""
        try:
            from pymodbus.client import ModbusTcpClient

            from .protocols.modbus import modbus_unit_kwargs

            def _query():
                client = ModbusTcpClient(
                    plc_info.ip_address,
                    port=plc_info.port or 502,
                    # Discovery timeout (1 s by default), not the 5 s read
                    # timeout: devices that ignore FC43 must not stall a scan
                    timeout=self.config.discovery_timeout_ms / 1000,
                    retries=0,
                )

                if client.connect():
                    try:
                        # Try to read device identification (MEI)
                        method = client.read_device_information
                        response = method(
                            read_code=0x01, object_id=0x00, **modbus_unit_kwargs(method, 1)  # Basic identification
                        )

                        if response and not response.isError():
                            info = response.information

                            def text(key: int) -> str:
                                return str(info.get(key, b"").decode("utf-8", errors="ignore")).strip()

                            # Keep values found earlier (e.g. MAC OUI) when a field is empty
                            plc_info.manufacturer = text(0) or plc_info.manufacturer
                            plc_info.model = text(1) or plc_info.model or "Modbus/TCP対応機器"
                            plc_info.firmware_version = text(2) or plc_info.firmware_version
                        else:
                            plc_info.model = plc_info.model or "Modbus/TCP対応機器"
                    except Exception:
                        plc_info.model = "Modbus/TCP対応機器"
                    finally:
                        client.close()

                return plc_info

            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, _query)

        except ImportError:
            logger.debug("pymodbus not available")
        except Exception as e:
            logger.debug(f"Modbus query failed: {e}")

        return plc_info

    async def _query_s7_info(self, plc_info: PLCInfo) -> PLCInfo:
        """Query Siemens S7 device for CPU information"""
        # The probe already verified S7comm (a Siemens protocol): keep the
        # manufacturer even when the CPU identification below fails or is
        # too slow (unsupported SZL request, busy CPU)
        plc_info.manufacturer = plc_info.manufacturer or "シーメンス"
        plc_info.model = plc_info.model or "S7 PLC"
        try:
            import snap7

            from .protocols.s7 import read_s7_identity

            def _query():
                client = snap7.client.Client()
                # S7-1200/1500 use slot 0, S7-300/400 slot 2 (as S7Handler)
                try:
                    try:
                        client.connect(plc_info.ip_address, 0, 0, plc_info.port or 102)
                    except Exception:
                        client.connect(plc_info.ip_address, 0, 2, plc_info.port or 102)
                except Exception:
                    # Neither slot: release the client (socket / native
                    # handle) instead of leaving it to the garbage collector
                    try:
                        client.disconnect()
                    except Exception as e:
                        logger.debug(f"S7 disconnect after failed connect: {e}")
                    raise

                # Fields are returned, not set here: after a timeout this
                # thread may still finish and must not change the result
                fields = {}
                try:
                    fields = read_s7_identity(client)
                except Exception as e:
                    logger.debug(f"S7 CPU identification failed: {e}")
                finally:
                    client.disconnect()
                return fields

            loop = asyncio.get_running_loop()
            # snap7 has no overall timeout: bound the identity query (two
            # connect attempts and one SZL read) so a slow host cannot stall
            # discovery; the protocol itself is already verified by the probe
            fields = await asyncio.wait_for(
                loop.run_in_executor(None, _query),
                timeout=3 * self.config.discovery_timeout_ms / 1000,
            )
            for name, value in fields.items():
                setattr(plc_info, name, value or getattr(plc_info, name))
            return plc_info

        except ImportError:
            logger.debug("snap7 not available")
        except Exception as e:
            logger.debug(f"S7 query failed: {e}")

        return plc_info

    async def _query_fins_info(self, plc_info: PLCInfo) -> PLCInfo:
        """Query FINS device for information"""
        try:
            from .config import DeviceType, StatusCode
            from .protocols.fins import FINSHandler

            # Simple read to confirm connection
            handler = FINSHandler(
                ip_address=plc_info.ip_address,
                port=plc_info.port or 9600,
                config=self.config,
                use_tcp=plc_info.protocol == Protocol.FINS_TCP,
            )

            if await handler.connect():
                try:
                    # CPU model and version (Controller Data Read, 05 01)
                    controller = await handler.read_controller_data()
                    if controller:
                        plc_info.manufacturer = plc_info.manufacturer or "オムロン"
                        plc_info.model = controller["model"]
                        plc_info.firmware_version = controller["version"] or plc_info.firmware_version
                    else:
                        data, status = await handler.read_device_raw(DeviceType.DM, 0, 1)
                        if status == StatusCode.OK:
                            plc_info.manufacturer = plc_info.manufacturer or "オムロン"
                            plc_info.model = plc_info.model or "FINS対応PLC"
                finally:
                    await handler.disconnect()
        except Exception as e:
            logger.debug(f"FINS query failed: {e}")

        return plc_info

    def get_results(self) -> List[PLCInfo]:
        """Get all discovered PLCs"""
        return list(self.discovered_plcs.values())

    def clear(self):
        """Clear discovery results"""
        self.discovered_plcs.clear()


async def discover_plcs(
    ip_range: Optional[str] = None,
    config: Optional[NetworkConfig] = None,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
    protocols: Optional[List[Protocol]] = None,
) -> List[PLCInfo]:
    """
    Convenience function to discover PLCs.

    Args:
        ip_range: Optional IP range to scan. If None, scans same segment.
        config: Optional network configuration.
        progress_callback: Optional callback for progress updates.

    Returns:
        List of discovered PLCInfo objects.
    """
    discovery = PLCDiscovery(config, protocols)

    if progress_callback:
        discovery.set_progress_callback(progress_callback)

    if ip_range:
        return await discovery.discover_ip_range(ip_range)
    else:
        return await discovery.discover_same_segment()
