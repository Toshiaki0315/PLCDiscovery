#!/usr/bin/env python3
"""
PLC Simulator Launcher

Starts all PLC simulators for comprehensive testing of the PLC Discovery tool.

Usage:
    python run_all.py [--host 127.0.0.1] [--delay MS] [--drop-denied] [--max-connections N]

This will start:
    - SLMP Simulator on port 5001
    - Modbus/TCP Simulator on port 1502
    - EtherNet/IP Simulator on port 44818
    - S7 Simulator on port 1102
    - FINS Simulator on port 9600 (UDP and TCP)
"""

import argparse
import asyncio
import logging
import signal
import sys
from typing import List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("PLC-Simulator-Launcher")

# Import simulators (support both direct execution and package import)
try:
    from .common import Faults, add_fault_options, faults_from_args, log_faults, with_datagram_faults, with_faults
    from .ethernet_ip_simulator import EtherNetIPDevice, EtherNetIPProtocol
    from .fins_simulator import FINSSimulator, FINSTCPServerProtocol, FINSUDPServerProtocol
    from .modbus_simulator import ModbusDevice, ModbusProtocol
    from .s7_simulator import COTPProtocol, S7Device
    from .slmp_simulator import SLMPDevice, SLMPProtocol
except ImportError:
    from common import (  # type: ignore[no-redef]
        Faults,
        add_fault_options,
        faults_from_args,
        log_faults,
        with_datagram_faults,
        with_faults,
    )
    from ethernet_ip_simulator import EtherNetIPDevice, EtherNetIPProtocol  # type: ignore[no-redef]
    from fins_simulator import FINSSimulator, FINSTCPServerProtocol, FINSUDPServerProtocol  # type: ignore[no-redef]
    from modbus_simulator import ModbusDevice, ModbusProtocol  # type: ignore[no-redef]
    from s7_simulator import COTPProtocol, S7Device  # type: ignore[no-redef]
    from slmp_simulator import SLMPDevice, SLMPProtocol  # type: ignore[no-redef]


class SimulatorManager:
    """Manages all PLC simulators"""

    def __init__(self, host: str = "127.0.0.1", faults: Optional[Faults] = None):
        self.host = host
        # Late / dropped answers and the connection limit, for every TCP server
        self.faults = faults
        self.servers: List[asyncio.AbstractServer] = []

        # Default denied ranges for each simulator
        self.slmp_denied = [(5000, 5100), (7000, 7050)]
        self.modbus_denied = [(5000, 5100), (8000, 8050)]
        self.eip_denied = [(100, 150)]
        self.s7_denied = [(500, 550)]
        # FINS: fixed in the simulator itself (fins_simulator.INACCESSIBLE_RANGES)

        # UDP transports
        self.udp_transports: List[asyncio.DatagramTransport] = []

    async def start_all(self):
        """Start all simulators"""
        logger.info("=" * 60)
        logger.info("Starting PLC Simulators")
        logger.info("=" * 60)

        loop = asyncio.get_event_loop()

        # SLMP Simulator
        try:
            slmp_device = SLMPDevice(self.slmp_denied)
            slmp_server = await loop.create_server(
                with_faults(lambda: SLMPProtocol(slmp_device), self.faults, slmp_device), self.host, 5001
            )
            self.servers.append(slmp_server)
            logger.info(f"✓ SLMP Simulator started on {self.host}:5001")
            logger.info(f"  Denied ranges: {self.slmp_denied}")
        except Exception as e:
            logger.error(f"✗ Failed to start SLMP Simulator: {e}")

        # Modbus Simulator
        try:
            modbus_device = ModbusDevice(self.modbus_denied)
            modbus_factory = with_faults(lambda: ModbusProtocol(modbus_device), self.faults, modbus_device)
            # Using 1502 instead of 502 (non-privileged)
            modbus_server = await loop.create_server(modbus_factory, self.host, 1502)
            self.servers.append(modbus_server)
            logger.info(f"✓ Modbus/TCP Simulator started on {self.host}:1502")
            logger.info("  (Note: Using port 1502 instead of 502 to avoid privileged port)")
            logger.info(f"  Denied ranges: {self.modbus_denied}")
        except Exception as e:
            logger.error(f"✗ Failed to start Modbus Simulator: {e}")

        # EtherNet/IP Simulator
        try:
            eip_device = EtherNetIPDevice(self.eip_denied)
            eip_server = await loop.create_server(
                with_faults(lambda: EtherNetIPProtocol(eip_device), self.faults, eip_device), self.host, 44818
            )
            self.servers.append(eip_server)
            logger.info(f"✓ EtherNet/IP Simulator started on {self.host}:44818")
            logger.info(f"  Denied ranges: {self.eip_denied}")
        except Exception as e:
            logger.error(f"✗ Failed to start EtherNet/IP Simulator: {e}")

        # EtherNet/IP Logix Simulator (symbolic tags, pycomm3 LogixDriver)
        try:
            logix_device = EtherNetIPDevice(mode="logix")
            logix_server = await loop.create_server(
                with_faults(lambda: EtherNetIPProtocol(logix_device), self.faults, logix_device), self.host, 44819
            )
            self.servers.append(logix_server)
            logger.info(f"✓ EtherNet/IP Logix Simulator started on {self.host}:44819")
            logger.info(f"  Tags: {', '.join(logix_device.logix_tags)}")
        except Exception as e:
            logger.error(f"✗ Failed to start EtherNet/IP Logix Simulator: {e}")

        # EtherNet/IP Omron NJ/NX Simulator (variables read by name)
        try:
            omron_device = EtherNetIPDevice(mode="omron")
            omron_server = await loop.create_server(
                with_faults(lambda: EtherNetIPProtocol(omron_device), self.faults, omron_device), self.host, 44820
            )
            self.servers.append(omron_server)
            logger.info(f"✓ EtherNet/IP Omron NJ/NX Simulator started on {self.host}:44820")
            logger.info(f"  Variables: {', '.join(omron_device.logix_tags)}")
        except Exception as e:
            logger.error(f"✗ Failed to start EtherNet/IP Omron NJ/NX Simulator: {e}")

        # S7 Simulator
        try:
            s7_device = S7Device(self.s7_denied)
            s7_factory = with_faults(lambda: COTPProtocol(s7_device), self.faults, s7_device)
            # Using 1102 instead of 102 (non-privileged)
            s7_server = await loop.create_server(s7_factory, self.host, 1102)
            self.servers.append(s7_server)
            logger.info(f"✓ S7 Simulator started on {self.host}:1102")
            logger.info("  (Note: Using port 1102 instead of 102 to avoid privileged port)")
            logger.info(f"  Denied ranges: {self.s7_denied}")
        except Exception as e:
            logger.error(f"✗ Failed to start S7 Simulator: {e}")

        # FINS Simulator (UDP and TCP on the same port, sharing one memory image)
        try:
            fins_simulator = FINSSimulator(self.host, 9600)
            transport, protocol = await loop.create_datagram_endpoint(
                with_datagram_faults(lambda: FINSUDPServerProtocol(fins_simulator), self.faults, fins_simulator),
                local_addr=(self.host, 9600),
            )
            try:
                fins_tcp_server = await loop.create_server(
                    with_faults(lambda: FINSTCPServerProtocol(fins_simulator), self.faults, fins_simulator),
                    self.host,
                    9600,
                )
            except Exception:
                transport.close()  # not half a simulator: "failed" means nothing is listening
                raise
            self.udp_transports.append(transport)
            self.servers.append(fins_tcp_server)
            logger.info(f"✓ FINS Simulator started on {self.host}:9600 (UDP + TCP)")
            logger.info("  Denied ranges: DM5000-5100, HR300-350")
        except Exception as e:
            logger.error(f"✗ Failed to start FINS Simulator: {e}")

        log_faults(self.faults, logger)
        logger.info("")
        logger.info("=" * 60)
        logger.info(f"All simulators running. {len(self.servers)} server(s) active.")
        logger.info("Press Ctrl+C to stop all simulators.")
        logger.info("=" * 60)
        logger.info("")

        # Print test commands (Modbus and S7 use non-privileged ports)
        target = "127.0.0.1" if self.host in ("0.0.0.0", "") else self.host
        # Discovery probes the simulators' own ports (1502, 1102, 44819,
        # 44820) on loopback addresses only; elsewhere the standard ports
        found = (
            "finds every simulator"
            if target.startswith("127.")
            else "finds SLMP, EtherNet/IP (44818), FINS on their standard ports"
        )
        commands = [
            (f"Discover ({found})", f"--mode discover --ip-range {target}"),
            ("SLMP", f"--mode range --target {target} --protocol slmp --device D --range 0-99"),
            ("Modbus/TCP", f"--mode range --target {target} --protocol modbus --port 1502 --device HR --range 0-99"),
            ("S7", f"--mode range --target {target} --protocol s7 --port 1102 --device DB --range 0-99"),
            ("FINS/UDP", f"--mode range --target {target} --protocol fins --device DM --range 0-99"),
            ("FINS/TCP", f"--mode range --target {target} --protocol fins-tcp --device DM --range 0-99"),
        ]
        logger.info("Test commands (plc_scanner.py / plc_scanner.bat / ./plc_scanner.sh):")
        for title, arguments in commands:
            logger.info(f"  # {title}")
            logger.info(f"  python plc_scanner.py {arguments}")
        logger.info("")

    async def stop_all(self):
        """Stop all simulators"""
        logger.info("Stopping all simulators...")
        for server in self.servers:
            server.close()
        if self.servers:
            # wait_closed() waits for connected clients (Python 3.12+): all
            # servers together, 2 s in all (it was 2 s for each of them)
            _, pending = await asyncio.wait(
                [asyncio.ensure_future(server.wait_closed()) for server in self.servers], timeout=2
            )
            for waiting in pending:
                waiting.cancel()
            if pending:
                logger.info("Simulators stopped with clients still connected")
        for transport in self.udp_transports:
            transport.close()
        logger.info("All simulators stopped.")

    async def run_forever(self):
        """Run until interrupted"""
        if not self.servers:
            return  # nothing could be started
        # The servers are already listening. Not serve_forever(): since
        # Python 3.12 its cancellation waits for every connected client, so
        # Ctrl+C had to be pressed twice while a scanner was connected.
        # stop_all() closes them with a bounded wait.
        await asyncio.Event().wait()


async def main(host: str, faults: Optional[Faults] = None) -> bool:
    """Main entry point"""
    manager = SimulatorManager(host, faults)

    # Handle shutdown signals
    loop = asyncio.get_event_loop()

    def signal_handler():
        logger.info("\nReceived shutdown signal...")
        for task in asyncio.all_tasks(loop):
            task.cancel()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
            # Windows event loops have no signal handlers: Ctrl+C arrives
            # as KeyboardInterrupt instead (handled where main() is run)
            break

    try:
        await manager.start_all()
        await manager.run_forever()
    except asyncio.CancelledError:
        pass
    finally:
        await manager.stop_all()
    # False when no simulator could be started (every port in use: a second
    # instance, or the simulator GUI is running)
    return bool(getattr(manager, "servers", True))


def run():
    parser = argparse.ArgumentParser(description="PLC Simulator Launcher")
    parser.add_argument(
        "--host", default="127.0.0.1", help="Host to bind to (default 127.0.0.1; 0.0.0.0 = all interfaces)"
    )
    add_fault_options(parser)
    args = parser.parse_args()

    try:
        started = asyncio.run(main(args.host, faults_from_args(args)))
    except (KeyboardInterrupt, asyncio.CancelledError):
        # (CancelledError: a second Ctrl+C while the simulators were stopping
        # ended in a traceback and exit code 1, which the launchers report
        # as "could not be started")
        return
    if not started:
        # The launchers (start_simulators.*) report the failure on this
        logger.error("No simulator could be started.")
        sys.exit(1)


if __name__ == "__main__":
    run()
