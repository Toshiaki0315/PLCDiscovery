"""
Modbus/TCP Protocol Handler

Supports:
- Modbus/TCP compatible PLCs (Schneider, ABB, Siemens, etc.)
- Function codes: 01 (Read Coils), 02 (Read Discrete Inputs),
                  03 (Read Holding Registers), 04 (Read Input Registers)
"""

import asyncio
import inspect
import logging
from typing import Any, List, Mapping, Optional, Tuple

from ..config import PROTOCOL_PORTS, DeviceType, Protocol, StatusCode
from .base import BaseProtocolHandler

logger = logging.getLogger(__name__)

# Device type mapping to Modbus function type
MODBUS_DEVICE_MAP = {
    DeviceType.D: "holding",  # Holding Registers (like D registers)
    DeviceType.HR: "holding",  # Holding Registers
    DeviceType.IR: "input",  # Input Registers
    DeviceType.M: "coil",  # Coils (like M relays)
    DeviceType.W: "holding",  # Holding Registers
    DeviceType.R: "input",  # Input Registers
    DeviceType.X: "discrete",  # Discrete Inputs
    DeviceType.Y: "coil",  # Coils
}

# pymodbus client method reading each Modbus table
MODBUS_READ_METHODS = {
    "holding": "read_holding_registers",
    "input": "read_input_registers",
    "coil": "read_coils",
    "discrete": "read_discrete_inputs",
}

# Tables answered as bits (the others as 16-bit registers)
MODBUS_BIT_TYPES = frozenset({"coil", "discrete"})


def modbus_unit_kwargs(method: Any, unit_id: int) -> dict:
    """
    Keyword argument selecting the unit/device for a pymodbus client call.

    The name changed across pymodbus 3.x: ``slave=`` (3.0 - 3.9) became
    ``device_id=`` (3.10+). Pick whichever the installed version accepts.
    """
    params: Mapping[str, Any]
    try:
        params = inspect.signature(method).parameters
    except (TypeError, ValueError):
        params = {}
    for name in ("device_id", "slave", "unit"):
        if name in params:
            return {name: unit_id}
    return {"device_id": unit_id}


# Exception codes about the requested range, answered by the device:
#   02 Illegal Data Address - start or start + quantity not valid
#   03 Illegal Data Value   - quantity not accepted (devices limited to fewer
#                             registers per request than the 100 read here)
# Both used to fall into NG_COMM_ERROR for 03: retries, then the whole
# range reported as communication errors although every register could be
# read in smaller requests.
MODBUS_SPLITTABLE_EXCEPTIONS = (0x02, 0x03)

# Modbus TCP constants
MODBUS_PORT = 502
MODBUS_MAX_READ_REGISTERS = 125  # Protocol maximum (reads use SAFE_READ_WORDS = 100)
MODBUS_MAX_READ_COILS = 2000  # Maximum coils per request


class ModbusHandler(BaseProtocolHandler):
    """
    Modbus/TCP Protocol Handler

    Implements communication with Modbus/TCP compatible PLCs
    using the pymodbus library.
    """

    protocol = Protocol.MODBUS_TCP
    MAX_ADDRESS = 0xFFFF  # 16-bit register/coil address

    def __init__(self, ip_address: str, port: Optional[int] = None, unit_id: int = 1, **kwargs: Any):
        super().__init__(ip_address, port or PROTOCOL_PORTS.get(Protocol.MODBUS_TCP, MODBUS_PORT), **kwargs)
        self._client: Any = None
        self._unit_id = unit_id

    async def connect(self) -> bool:
        """Establish Modbus/TCP connection"""
        try:
            from pymodbus.client import ModbusTcpClient

            def _connect():
                client = ModbusTcpClient(
                    host=self.ip_address,
                    port=self.port,
                    timeout=self.config.request_timeout_ms / 1000,
                    # Retries are handled by BaseProtocolHandler; pymodbus'
                    # own retries (default 3) would multiply PLC requests
                    retries=0,
                )
                if client.connect():
                    return client
                return None

            loop = asyncio.get_running_loop()
            self._client = await loop.run_in_executor(None, _connect)

            if self._client:
                self._connected = True
                logger.info(f"Modbus connected to {self.ip_address}:{self.port}")
                return True
            else:
                logger.error(f"Modbus connection failed: {self.ip_address}:{self.port}")
                return False

        except ImportError:
            logger.error("pymodbus library not installed")
            return False
        except Exception as e:
            logger.error(f"Modbus connection failed: {e}")
            self._connected = False
            return False

    async def disconnect(self):
        """Close Modbus/TCP connection"""
        if self._client:
            try:

                def _disconnect():
                    self._client.close()

                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, _disconnect)
            except Exception as e:
                logger.debug(f"Modbus disconnect error: {e}")
            finally:
                self._client = None
                self._connected = False
                logger.info(f"Modbus disconnected from {self.ip_address}")

    async def read_device_raw(
        self, device_type: DeviceType, start_address: int, count: int
    ) -> Tuple[Optional[List[int]], StatusCode]:
        """
        Read device data using Modbus/TCP protocol.

        Args:
            device_type: Device type (D, HR, IR, M, etc.)
            start_address: Starting address
            count: Number of points to read

        Returns:
            Tuple of (data list or None, status code)
        """
        if not await self._ensure_fresh_connection():
            return None, StatusCode.NG_COMM_ERROR
        if not self._connected or not self._client:
            return None, StatusCode.NG_COMM_ERROR

        # Get Modbus device type
        modbus_type = MODBUS_DEVICE_MAP.get(device_type)
        if not modbus_type:
            logger.warning(f"Unsupported device type for Modbus: {device_type}")
            return None, StatusCode.NG_UNSUPPORTED

        try:

            def _read():
                method = getattr(self._client, MODBUS_READ_METHODS[modbus_type])
                return method(start_address, count=count, **modbus_unit_kwargs(method, self._unit_id))

            result = await self._run_blocking(_read)

            if result is None:
                return None, StatusCode.NG_COMM_ERROR

            # Check for errors
            if result.isError():
                # Get exception code if available
                exception_code = getattr(result, "exception_code", 0)
                if exception_code in MODBUS_SPLITTABLE_EXCEPTIONS:
                    # The device answered about this request's addresses or
                    # quantity: binary search narrows it down (a device that
                    # reads at most e.g. 32 registers answers 03 to 100)
                    logger.debug(f"Modbus exception {exception_code}: {device_type.value}{start_address} x{count}")
                    return None, StatusCode.NG_ILLEGAL_ADDR
                elif exception_code == 1:  # Illegal function
                    logger.debug(f"Modbus illegal function: {device_type.value}")
                    return None, StatusCode.NG_UNSUPPORTED
                else:
                    logger.debug(f"Modbus error: exception_code={exception_code}")
                    return None, StatusCode.NG_COMM_ERROR

            # Extract data
            if modbus_type in MODBUS_BIT_TYPES:
                # pymodbus pads the bit list to a multiple of 8; keep only
                # the requested points so addresses are not duplicated
                data = [1 if bit else 0 for bit in result.bits[:count]]
            else:
                data = list(result.registers)

            return data, StatusCode.OK

        except asyncio.TimeoutError:
            logger.debug(f"Modbus read timeout: {device_type.value}{start_address}")
            return None, StatusCode.NG_TIMEOUT
        except Exception as e:
            logger.debug(f"Modbus read error: {e}")
            return None, StatusCode.NG_COMM_ERROR


class ModbusRTUOverTCPHandler(ModbusHandler):
    """
    Modbus RTU over TCP Handler

    For devices that use Modbus RTU framing over TCP
    (common in serial-to-Ethernet converters).
    """

    def __init__(self, ip_address: str, port: Optional[int] = None, **kwargs: Any):
        super().__init__(ip_address, port or 502, **kwargs)

    # Note: RTU over TCP uses the same client as standard Modbus TCP
    # The framing is handled by some serial gateways transparently
