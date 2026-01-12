#!/usr/bin/env python3
"""
FINS Protocol Simulator

Simulates an Omron PLC with FINS/UDP protocol support.
Used for testing without actual PLC hardware.

Usage:
    python fins_simulator.py [--port 9600] [--host 0.0.0.0]
"""

import asyncio
import struct
import logging
import argparse
import random
from typing import Dict, Tuple

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# FINS Constants
FINS_ICF_RESPONSE = 0xC0  # Response frame
FINS_CMD_MEMORY_READ = (0x01, 0x01)

# Memory area codes
FINS_AREA_DM = 0x82
FINS_AREA_HR = 0xB2
FINS_AREA_W = 0xB1

# Simulated inaccessible ranges
INACCESSIBLE_RANGES = [
    (FINS_AREA_DM, 5000, 5100),  # DM5000-5100
    (FINS_AREA_HR, 1000, 1050),   # HR1000-1050
]


class FINSSimulator:
    """Simulates an Omron PLC with FINS protocol"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 9600):
        self.host = host
        self.port = port
        self._running = False
        
        # Simulated memory areas
        self._dm_area: Dict[int, int] = {}  # DM area (0x82)
        self._hr_area: Dict[int, int] = {}  # HR area (0xB2)
        self._w_area: Dict[int, int] = {}   # W area (0xB1)
        
        # Initialize with sample data
        self._initialize_sample_data()
    
    def _initialize_sample_data(self):
        """Initialize memory areas with sample data"""
        # DM Area: Various data patterns
        for i in range(1000):
            if i < 100:
                # Temperature values (scaled by 10)
                self._dm_area[i] = 200 + random.randint(-20, 50)
            elif i < 200:
                # Counter values
                self._dm_area[i] = i * 10
            elif i < 300:
                # Random production data
                self._dm_area[i] = random.randint(0, 65535)
            else:
                # Sequential pattern
                self._dm_area[i] = i
        
        # HR Area: Holding registers
        for i in range(500):
            self._hr_area[i] = i * 2
        
        # W Area: Work registers
        for i in range(200):
            self._w_area[i] = random.randint(0, 255)
        
        logger.info(f"Initialized DM: {len(self._dm_area)} words")
        logger.info(f"Initialized HR: {len(self._hr_area)} words")
        logger.info(f"Initialized W: {len(self._w_area)} words")
    
    def _get_memory_area(self, area_code: int) -> Dict[int, int]:
        """Get memory area dictionary by code"""
        if area_code == FINS_AREA_DM:
            return self._dm_area
        elif area_code == FINS_AREA_HR:
            return self._hr_area
        elif area_code == FINS_AREA_W:
            return self._w_area
        else:
            return {}
    
    def _is_accessible(self, area_code: int, address: int) -> bool:
        """Check if address is accessible"""
        for area, start, end in INACCESSIBLE_RANGES:
            if area == area_code and start <= address <= end:
                return False
        return True
    
    def _handle_read_command(
        self,
        request: bytes,
        client_addr: Tuple[str, int]
    ) -> bytes:
        """Handle memory area read command"""
        # Parse request
        # Format: Header(10) + Cmd(2) + AreaCode(1) + AddrHigh(1) + AddrLow(1) + Bit(1) + CountHigh(1) + CountLow(1)
        if len(request) < 18:
            return self._build_error_response(request, 0x0401)
        
        area_code = request[12]
        addr_high = request[13]
        addr_low = request[14]
        start_address = (addr_high << 8) | addr_low
        count_high = request[16]
        count_low = request[17]
        count = (count_high << 8) | count_low
        
        logger.debug(
            f"Read request: area=0x{area_code:02X}, "
            f"addr={start_address}, count={count}"
        )
        
        # Check accessibility
        for addr in range(start_address, start_address + count):
            if not self._is_accessible(area_code, addr):
                logger.warning(
                    f"Inaccessible address: area=0x{area_code:02X}, addr={addr}"
                )
                return self._build_error_response(request, 0x1002)
        
        # Get memory area
        memory = self._get_memory_area(area_code)
        
        # Build response data
        data = []
        for addr in range(start_address, start_address + count):
            value = memory.get(addr, 0)
            data.append((value >> 8) & 0xFF)  # High byte
            data.append(value & 0xFF)          # Low byte
        
        return self._build_success_response(request, bytes(data))
    
    def _build_success_response(self, request: bytes, data: bytes) -> bytes:
        """Build successful response frame"""
        # Response header
        header = bytes([
            FINS_ICF_RESPONSE,  # ICF (response)
            request[1],          # RSV
            request[2],          # GCT
            request[6],          # DNA (swap with source)
            request[7],          # DA1
            request[8],          # DA2
            request[3],          # SNA
            request[4],          # SA1
            request[5],          # SA2
            request[9],          # SID
        ])
        
        # Command code
        cmd = bytes([request[10], request[11]])
        
        # End code (success)
        end_code = bytes([0x00, 0x00])
        
        return header + cmd + end_code + data
    
    def _build_error_response(self, request: bytes, error_code: int) -> bytes:
        """Build error response frame"""
        # Response header
        header = bytes([
            FINS_ICF_RESPONSE,
            request[1],
            request[2],
            request[6],
            request[7],
            request[8],
            request[3],
            request[4],
            request[5],
            request[9],
        ])
        
        # Command code
        cmd = bytes([request[10], request[11]])
        
        # End code (error)
        end_code = bytes([
            (error_code >> 8) & 0xFF,
            error_code & 0xFF
        ])
        
        return header + cmd + end_code


class FINSUDPServerProtocol(asyncio.DatagramProtocol):
    """UDP Protocol handler for FINS simulator"""
    
    def __init__(self, simulator: FINSSimulator):
        self.simulator = simulator
        self.transport = None
    
    def connection_made(self, transport):
        self.transport = transport
        logger.info("FINS UDP server ready")
    
    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        logger.debug(f"Received {len(data)} bytes from {addr}")
        
        # Check minimum frame size
        if len(data) < 12:
            logger.warning("Invalid FINS frame (too short)")
            return
        
        # Parse command code
        cmd_main = data[10]
        cmd_sub = data[11]
        
        if (cmd_main, cmd_sub) == FINS_CMD_MEMORY_READ:
            response = self.simulator._handle_read_command(data, addr)
            self.transport.sendto(response, addr)
        else:
            logger.warning(f"Unknown command: {cmd_main:02X} {cmd_sub:02X}")
            response = self.simulator._build_error_response(data, 0x0401)
            self.transport.sendto(response, addr)


async def run_fins_simulator(host: str, port: int):
    """Run FINS simulator server"""
    simulator = FINSSimulator(host, port)
    
    loop = asyncio.get_event_loop()
    
    # Create UDP endpoint
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: FINSUDPServerProtocol(simulator),
        local_addr=(host, port)
    )
    
    logger.info(f"FINS Simulator started on {host}:{port}")
    logger.info("Memory areas:")
    logger.info(f"  DM Area (0x82): 0-999 (accessible)")
    logger.info(f"  DM Area (0x82): 5000-5100 (INACCESSIBLE)")
    logger.info(f"  HR Area (0xB2): 0-499 (accessible)")
    logger.info(f"  HR Area (0xB2): 1000-1050 (INACCESSIBLE)")
    logger.info(f"  W Area (0xB1): 0-199 (accessible)")
    
    try:
        # Keep running
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        logger.info("FINS Simulator shutting down...")
    finally:
        transport.close()


def main():
    parser = argparse.ArgumentParser(
        description="FINS Protocol Simulator for Omron PLCs"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=9600,
        help="Port to listen on (default: 9600)"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        asyncio.run(run_fins_simulator(args.host, args.port))
    except KeyboardInterrupt:
        logger.info("Simulator stopped by user")


if __name__ == "__main__":
    main()


