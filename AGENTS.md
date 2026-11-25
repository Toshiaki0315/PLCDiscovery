# AGENTS.md

This file provides guidance to Codex (claude.ai/code) when working with code in this repository.

## Project Overview

This is a multi-vendor PLC (Programmable Logic Controller) automatic discovery and data collection tool for factory maintenance and diagnostics. The tool scans factory networks to detect PLCs from various manufacturers (Mitsubishi, Keyence, Omron, Siemens, etc.) and collects device data in read-only mode.

**Primary Objectives (in priority order):**
1. **Never stop on errors** - Continue processing even when communication errors occur
2. **Accurate reporting** - Include which addresses are inaccessible in the complete list
3. **Never stop PLCs** - Read-only access with proper wait handling for production safety
4. **Easy data analysis** - CSV output with hexadecimal data preservation

## System Architecture

### Core Components

The system is designed around three main functional areas:

1. **Discovery Module**: Network scanning to detect PLCs
   - Same-segment UDP broadcast discovery (Phase 1 - priority)
   - User-specified IP range scanning (Phase 2 - optional)
   - Multi-protocol detection: SLMP (port 5001), EtherNet/IP (port 44818), Modbus/TCP (port 502), S7 (port 102)

2. **Data Collection Module**: Read-only data retrieval
   - **Full Scan Mode**: For factory downtime - retrieves maximum device ranges (D, M, R, DM, etc.)
   - **Range Specified Mode**: For production time - retrieves user-specified ranges with periodic execution

3. **Error Recovery with Binary Search Algorithm**: Critical failure-resistant design
   - When a read request fails, splits the range in half and retries recursively
   - Continues down to single-address level to identify exactly which addresses are inaccessible
   - Session-based learning: skips known-bad addresses in subsequent scans

### Protocol Support (Priority Order)

**Priority 1:**
- SLMP/MC Protocol (3E Frame): Mitsubishi, Keyence, Panasonic, Toshiba, Hitachi, Sharp
- EtherNet/IP (CIP): Omron, Rockwell, Keyence, Yaskawa, JTEKT, CODESYS

**Priority 2:**
- Modbus/TCP: Yokogawa, Fuji Electric, IDEC, Delta, Yaskawa, JTEKT, GE
- Proprietary: S7 (Siemens), FINS (Omron legacy)

### Automatic Packet Splitting

Each protocol has maximum communication limits that are automatically handled:
- SLMP (3E Frame): 960 words max, 900 words recommended
- S7: 111 words per request (222 bytes: one request on the smallest PDU, 240 bytes)
- Modbus/TCP (FC03/04): 125 words max, 100 words recommended
- EtherNet/IP (CIP): 252 words max, 200 words recommended

## Common Commands

### Development Setup
```bash
# Install dependencies
pip install pymcprotocol>=0.3.0      # SLMP (Mitsubishi/Keyence)
pip install pycomm3>=1.2.0           # EtherNet/IP (Omron/Rockwell)
pip install pymodbus>=3.0.0          # Modbus/TCP (Yokogawa/Fuji)
pip install python-snap7>=1.4.0      # S7 (Siemens)
pip install scapy>=2.5.0             # ARP/low-level discovery
```

### Running the Tool

**Discovery mode:**
```bash
# Same-segment discovery
python plc_scanner.py --mode discover

# User-specified IP range
python plc_scanner.py --mode discover --ip-range "192.168.1.0/24"
```

**Data collection modes:**
```bash
# Full scan mode (for maintenance/factory downtime)
python plc_scanner.py --mode full --target 192.168.1.10

# Range specified mode (for production time with periodic execution)
python plc_scanner.py --mode range --target 192.168.1.10 --device D --range 0-100 --interval 60
```

### Network Load Control Parameters

```bash
--packet-interval 50      # Wait time between packets (default: 50ms)
--retry-interval 200      # Wait time before retry (default: 200ms)
--max-concurrent 1        # Concurrent PLC scan count (default: 1)
--request-timeout 5000    # Request timeout (default: 5000ms)
```

## Key Implementation Guidelines

### Binary Search Error Recovery

This is the most critical algorithm in the system. When a read request fails:

```
1. Initial attempt: Read specified range (e.g., D0-D959)
2. On error: Split in half → D0-D479 and D480-D959
3. Continue recursively until reaching single-address granularity
4. Mark single-address failures as "inaccessible"
5. Session learning: Cache inaccessible addresses (Set type, O(1) lookup)
```

Wholly invalid ranges: before splitting a range of 4+ addresses that failed
with NG_ILLEGAL_ADDR, its first and last address are read alone. If both are
NG_ILLEGAL_ADDR, the whole range is reported (and learned) as NG_ILLEGAL_ADDR
without further splitting. Splitting such a range down to single addresses
costs about 2N requests (an unconfigured R0-R32767: ~65,000 requests and
hours of waiting); the edge check needs ~3 per chunk. Accepted trade-off: a
readable island strictly inside a range whose both ends are invalid is
reported as NG_ILLEGAL_ADDR.

The edge check is a per-handler flag (`EDGE_PROBE_SHORTCUT`) and is off for
Modbus/TCP: register maps are sparse there, so every address of a failed
range is confirmed on its own (about 2N requests for a wholly invalid range).

Unanswered ranges: a chunk that times out although the PLC answered the
request before it is halved as well (`_search_unanswered`), because some
devices drop a request touching an invalid address instead of answering an
error. A half that stays unanswered is searched further only after the PLC
answered a read of the last address it was known to answer; otherwise the
link is taken to be down and nothing more is sent. A single address that
stays unanswered when checked twice is learned for the session as
NG_TIMEOUT. Each unanswered request costs a full timeout, so the search is
bounded: `UNANSWERED_SEARCH_BUDGET` (16) unanswered requests per
read_device_range() call and `UNANSWERED_SESSION_BUDGET` (96) per session;
what is left is reported with its status, not learned, and read with a
single request per scan from then on.

While nothing has been read at all, an unanswered range cannot be told from
a dead link. The first chunk of every later range is then asked once (also
counted against the session budget), so a device type the PLC does answer
is still read and gives the known-good address the search needs.

A scan in which the PLC answered nothing (every request NG_TIMEOUT /
NG_COMM_ERROR) is a failure and the target counts as unreachable, even if
the transport still looks connected (`scan_runner.plc_answered`). Addresses
reported from the session's learned set (`DataPoint.cached`, no request is
sent for them) and NG_UNSUPPORTED points are not answers of the PLC and do
not count either way.

**Constraints:**
- Maximum split depth: 12 levels (log2(4096))
- Estimated time per level: 100-500ms
- A lost link costs about 7 unanswered requests (the chunk with its
  retries, its two halves, and one read of the address the PLC answered
  last); the rest of the range is then reported without further requests.
  Every request that is not answered costs one request timeout (default 5 s).

### Data Output Files

The tool generates timestamped CSV files:
- `discovery_result_YYYYMMDD_HHMMSS.csv` - Detected PLC list with IP, MAC, manufacturer, model, protocol
- `plc_data_<IP>_YYYYMMDD_HHMMSS.csv` - Device data (address, value in hex, status, timestamp)
  (`plc_data_<IP>_<PROTOCOL>_<port>_...csv` when several targets share the IP;
  `..._<port>_unit_id2_...csv` when they also share protocol and port, see
  `discovery.target_instances`)
- `access_denied_log.csv` - Inaccessible addresses for reference in next session

### Critical Safety Requirements

1. **Read-Only Access**: No write functionality whatsoever
2. **Network Load Control**: Mandatory wait intervals between packets
3. **Timeout Handling**: Never hang indefinitely - use configurable timeouts
4. **Production Safety**: Never disrupt running PLCs with aggressive polling

## Technical Notes

### Status Codes in Output
- `OK`: Successfully retrieved
- `NG_ILLEGAL_ADDR`: Address invalid/undefined (confirmed via binary search)
- `NG_TIMEOUT`: Timeout after retry attempts
- `NG_COMM_ERROR`: Communication error
- `NG_UNSUPPORTED`: Device type not supported by this PLC model

### Multi-Protocol Manufacturer Handling

When a manufacturer supports multiple protocols (e.g., JTEKT, Yaskawa):
1. Prioritize faster response time during discovery
2. Prioritize protocols with richer data availability (SLMP/EIP over Modbus)
3. Follow manufacturer's official recommendations

### Session-Based Learning

Once an address is determined inaccessible, it's added to an in-memory Set. On subsequent scans within the same session (interval mode), these addresses are skipped to avoid cumulative timeout delays.

## Development Environment

- **Language**: Python 3.10+
- **UI**: Command-line interface (arguments or interactive)
- **Output**: CSV files (UTF-8 or Shift-JIS encoding)
- **Platform**: Cross-platform (Windows, macOS, Linux)
