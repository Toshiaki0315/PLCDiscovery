"""
The SLMP simulator as other SLMP clients (e.g. a device gateway) see it:
3E / 4E frames, Q and iQ-R device formats, batch / random / block reads,
CPU model name, loopback, framing and error answers.
"""

import logging
import socket
import struct
import time

import pymcprotocol
import pytest

from simulators.control import SimulatorController
from simulators.slmp_simulator import SLMPDevice

D, M, X = 0xA8, 0x90, 0x9C


@pytest.fixture(scope="module")
def simulator():
    controller = SimulatorController()
    port = controller.start("slmp", "127.0.0.1", 0)
    controller.write("slmp", "D", 5, 0x1234)
    controller.write("slmp", "D", 6, 0x0001)
    yield controller, port
    controller.shutdown()


@pytest.mark.parametrize(
    "client, plctype", [(pymcprotocol.Type3E, "Q"), (pymcprotocol.Type4E, "Q"), (pymcprotocol.Type3E, "iQ-R")]
)
def test_pymcprotocol_reads(simulator, client, plctype):
    _, port = simulator
    mc = client(plctype=plctype)
    mc.connect("127.0.0.1", port)
    try:
        assert mc.batchread_wordunits("D0", 3) == [0, 10, 20]
        assert mc.batchread_bitunits("M0", 5) == [0, 1, 0, 1, 0]  # M[n] = n % 2
        assert mc.batchread_wordunits("M0", 1) == [-21846]  # 0xAAAA: M0 is bit 0
        assert mc.randomread(word_devices=["D0", "D100", "M0"], dword_devices=["D5"]) == (
            [0, 0x1234, -21846],
            [0x0001_1234],
        )
        assert mc.read_cputype() == ("Q03UDVCPU", "0366")
    finally:
        mc.close()


def _frame(command, subcommand, data=b"", network=0, pc=0xFF, io=0x03FF, station=0):
    body = struct.pack("<HHH", 0x0010, command, subcommand) + data
    return struct.pack("<HBBHBH", 0x0050, network, pc, io, station, len(body)) + body


def _device(number, code):
    return struct.pack("<I", number)[:3] + bytes([code])


def _recv(sock, count=1):
    """``count`` 3E responses as (end code, data, route)"""
    sock.settimeout(3)
    buffer = b""
    responses = []
    while len(responses) < count:
        received = sock.recv(4096)
        assert received, "the simulator closed the connection"
        buffer += received
        while len(buffer) >= 9:
            length = struct.unpack("<H", buffer[7:9])[0]
            if len(buffer) < 9 + length:
                break
            frame, buffer = buffer[: 9 + length], buffer[9 + length :]
            assert frame[0:2] == b"\xd0\x00"
            responses.append((struct.unpack("<H", frame[9:11])[0], frame[11:], frame[2:7]))
    return responses


@pytest.fixture
def conn(simulator):
    _, port = simulator
    with socket.create_connection(("127.0.0.1", port)) as sock:
        yield sock


def _words(data):
    return list(struct.unpack(f"<{len(data) // 2}H", data))


def test_two_requests_in_one_packet_and_a_split_request(conn):
    first = _frame(0x0401, 0x0000, _device(1, D) + struct.pack("<H", 2))
    second = _frame(0x0401, 0x0000, _device(3, D) + struct.pack("<H", 1))
    conn.sendall(first + second[:5])  # the second arrives in two pieces
    conn.sendall(second[5:])
    (code1, data1, _), (code2, data2, _) = _recv(conn, 2)
    assert (code1, _words(data1)) == (0, [10, 20])
    assert (code2, _words(data2)) == (0, [30])


def test_block_read_words_and_bits(conn):
    data = bytes([1, 1]) + _device(0, D) + struct.pack("<H", 2) + _device(0, M) + struct.pack("<H", 1)
    conn.sendall(_frame(0x0406, 0x0000, data))
    ((code, payload, _),) = _recv(conn)
    assert code == 0 and _words(payload) == [0, 10, 0xAAAA]


def test_loopback(conn):
    conn.sendall(_frame(0x0619, 0x0000, struct.pack("<H", 5) + b"ABCDE"))
    ((code, payload, _),) = _recv(conn)
    assert code == 0 and payload == struct.pack("<H", 5) + b"ABCDE"


def test_four_e_frame_echoes_the_serial_number(simulator):
    _, port = simulator
    body = struct.pack("<HHH", 0x0010, 0x0401, 0x0000) + _device(2, D) + struct.pack("<H", 1)
    request = struct.pack("<HHH", 0x0054, 0xBEEF, 0) + struct.pack("<BBHBH", 0, 0xFF, 0x03FF, 0, len(body)) + body
    with socket.create_connection(("127.0.0.1", port)) as sock:
        sock.settimeout(3)
        sock.sendall(request)
        response = sock.recv(4096)
    assert response[0:6] == b"\xd4\x00" + struct.pack("<H", 0xBEEF) + b"\x00\x00"
    assert struct.unpack("<H", response[13:15])[0] == 0 and _words(response[15:]) == [20]


@pytest.mark.parametrize(
    "command, subcommand, data, end_code",
    [
        (0x1401, 0x0000, _device(0, D) + struct.pack("<HH", 1, 99), 0xC059),  # write: read-only
        (0x0401, 0x0000, _device(0, D) + struct.pack("<H", 961), 0xC051),  # over 960 words
        (0x0401, 0x0001, _device(0, D) + struct.pack("<H", 1), 0xC055),  # bit units on a word device
        (0x0401, 0x0000, _device(5000, D) + struct.pack("<H", 1), 0xC055),  # denied range
        (0x0401, 0x0000, _device(0, 0x01) + struct.pack("<H", 1), 0xC055),  # unknown device code
        (0x0401, 0x0000, _device(0, D), 0xC061),  # points missing
        (0x0403, 0x0000, bytes([193, 0]), 0xC051),  # over 192 random points
    ],
)
def test_errors_answer_with_end_code_and_route(conn, command, subcommand, data, end_code):
    conn.sendall(_frame(command, subcommand, data, network=1, pc=2, station=3))
    ((code, info, route),) = _recv(conn)
    assert code == end_code
    assert route == struct.pack("<BBHB", 1, 2, 0x03FF, 3)  # the request's route echoed
    assert info == route + struct.pack("<HH", command, subcommand)  # error information


def test_connection_survives_errors(conn):
    conn.sendall(_frame(0x1401, 0x0000) + _frame(0x0401, 0x0000, _device(0, D) + struct.pack("<H", 1)))
    (bad, _, _), (good, data, _) = _recv(conn, 2)
    assert bad == 0xC059 and good == 0 and _words(data) == [0]


def test_x_is_numbered_like_the_scanner_and_pymcprotocol(simulator):
    """X1F (hex, as in GX Works) is device number 31 in the frame and in the GUI"""
    controller, port = simulator
    controller.write("slmp", "X", 31, 1)
    mc = pymcprotocol.Type3E()
    mc.connect("127.0.0.1", port)
    try:
        assert mc.batchread_bitunits("X1F", 1) == [1]
    finally:
        mc.close()


def _polled_log(frames, repeat):
    """SLMP-Simulator log lines while one connection sends ``frames`` ``repeat`` times (own server)"""
    caplog_lines = []
    controller = SimulatorController()

    class Collect(logging.Handler):
        def emit(self, record):
            # The logger is shared by every SLMP server: keep only this
            # controller's (its own event loop thread), not a late
            # "Connection closed" from another test's server
            if record.thread == controller._thread.ident:
                caplog_lines.append((record.levelno, record.getMessage()))

    sim_logger = logging.getLogger("SLMP-Simulator")
    handler, old_level = Collect(logging.DEBUG), sim_logger.level
    sim_logger.addHandler(handler)
    sim_logger.setLevel(logging.DEBUG)
    try:
        port = controller.start("slmp", "127.0.0.1", 0, denied="5000-5100")
        with socket.create_connection(("127.0.0.1", port)) as sock:
            sock.sendall(b"".join(frames) * repeat)
            _recv(sock, len(frames) * repeat)
        deadline = time.time() + 3
        while not any(m.startswith("Connection closed") for _, m in caplog_lines) and time.time() < deadline:
            time.sleep(0.01)
    finally:
        controller.shutdown()
        sim_logger.removeHandler(handler)
        sim_logger.setLevel(old_level)
    lines = [m for level, m in caplog_lines if level >= logging.INFO]
    start = next(i for i, m in enumerate(lines) if m.startswith("Connection from"))
    return lines[start:]  # from the connection on (start-up lines dropped)


def test_polling_does_not_flood_the_log():
    """A gateway polls every few ms: reads log at DEBUG, connections and unsupported commands still show"""
    read = _frame(0x0401, 0x0000, _device(0, D) + struct.pack("<H", 1))
    random_read = _frame(0x0403, 0x0000, bytes([1, 0]) + _device(0, D))
    block_read = _frame(0x0406, 0x0000, bytes([1, 0]) + _device(0, D) + struct.pack("<H", 1))
    bit_read = _frame(0x0401, 0x0001, _device(0, M) + struct.pack("<H", 1))
    lines = _polled_log([read, random_read, block_read, bit_read], 25)
    assert [line.split(" ")[0] for line in lines] == ["Connection", "Connection"]


def test_repeated_errors_are_logged_once_per_connection():
    """Polling a denied address or an unsupported command shows each error once, not every few ms"""
    denied = _frame(0x0403, 0x0000, bytes([2, 0]) + _device(0, D) + _device(5000, D))
    write = _frame(0x1401, 0x0000)
    other_denied = _frame(0x0401, 0x0000, _device(5050, D) + struct.pack("<H", 1))
    lines = _polled_log([denied, write, other_denied], 30)
    assert lines[1:-1] == [
        "Command 0403: access denied: D5000",
        "Unsupported command: 1401 subcommand 0000",
        "Command 0401: access denied: D5050",
    ]


# --- device ranges and writes ----------------------------------------------


@pytest.fixture
def writable_port():
    controller = SimulatorController()
    port = controller.start("slmp", "127.0.0.1", 0, denied="5000-5100", writable=True)
    yield port
    controller.shutdown()


@pytest.mark.parametrize(
    "command, subcommand, data, end_code",
    [
        (0x0401, 0x0000, _device(12287, D) + struct.pack("<H", 1), 0),  # last D of a Q03UDVCPU
        (0x0401, 0x0000, _device(12287, D) + struct.pack("<H", 2), 0xC056),  # runs past it
        (0x0401, 0x0000, _device(12288, D) + struct.pack("<H", 1), 0xC056),
        (0x0401, 0x0000, _device(8176, M) + struct.pack("<H", 1), 0),  # M8176-M8191 as one word
        (0x0401, 0x0000, _device(8177, M) + struct.pack("<H", 1), 0xC056),
        (0x0401, 0x0001, _device(8192, X) + struct.pack("<H", 1), 0xC056),
    ],
)
def test_reads_past_the_last_device_number_answer_c056(conn, command, subcommand, data, end_code):
    conn.sendall(_frame(command, subcommand, data))
    ((code, _, _),) = _recv(conn)
    assert code == end_code


@pytest.mark.parametrize("client, plctype", [(pymcprotocol.Type3E, "Q"), (pymcprotocol.Type3E, "iQ-R")])
def test_writes_when_writable(writable_port, client, plctype):
    mc = client(plctype=plctype)
    mc.connect("127.0.0.1", writable_port)
    try:
        mc.batchwrite_wordunits("D10", [1, -2, 3])
        assert mc.batchread_wordunits("D10", 3) == [1, -2, 3]
        mc.batchwrite_bitunits("M200", [1, 0, 1])
        assert mc.batchread_bitunits("M200", 3) == [1, 0, 1]
        mc.randomwrite(["D20", "M300"], [7, 5], ["D30"], [0x0002_0001])  # M300 word: bits 0 and 2
        assert mc.batchread_wordunits("D20", 1) == [7]
        assert mc.batchread_bitunits("M300", 3) == [1, 0, 1]
        assert mc.batchread_wordunits("D30", 2) == [1, 2]  # low word first
        mc.randomwrite_bitunits(["M400", "Y1F"], [1, 1])
        assert mc.batchread_bitunits("M400", 1) == [1] and mc.batchread_bitunits("Y1F", 1) == [1]
    finally:
        mc.close()


def test_write_errors_and_nothing_half_written(writable_port):
    with socket.create_connection(("127.0.0.1", writable_port)) as sock:
        # random write: D0 fine, D5000 denied -> C055 and D0 untouched
        sock.sendall(
            _frame(0x1402, 0x0000, bytes([2, 0]) + _device(0, D) + b"\x09\x00" + _device(5000, D) + b"\x01\x00")
        )
        sock.sendall(_frame(0x1401, 0x0000, _device(12288, D) + struct.pack("<HH", 1, 1)))  # past D12287
        sock.sendall(_frame(0x1401, 0x0000, _device(0, D) + struct.pack("<H", 2) + b"\x01\x00"))  # data short
        sock.sendall(_frame(0x0401, 0x0000, _device(0, D) + struct.pack("<H", 1)))
        (denied, _, _), (past, _, _), (short, _, _), (read, data, _) = _recv(sock, 4)
    assert (denied, past, short) == (0xC055, 0xC056, 0xC061)
    assert read == 0 and _words(data) == [0]


def test_writes_are_refused_unless_writable(conn):
    conn.sendall(_frame(0x1401, 0x0000, _device(0, D) + struct.pack("<HH", 1, 99)))
    ((code, _, _),) = _recv(conn)
    assert code == 0xC059


def test_connection_closed_names_the_client():
    lines = _polled_log([_frame(0x0401, 0x0000, _device(0, D) + struct.pack("<H", 1))], 1)
    peer = lines[0].removeprefix("Connection from ")
    assert lines[-1] == f"Connection closed: {peer}" and ":" in peer


def test_r04cpu_answers_its_model_and_ranges():
    controller = SimulatorController()
    try:
        port = controller.start("slmp", "127.0.0.1", 0, cpu="R04CPU")
        mc = pymcprotocol.Type3E(plctype="iQ-R")
        mc.connect("127.0.0.1", port)
        try:
            assert mc.read_cputype() == ("R04CPU", "4800")
            assert mc.batchread_bitunits("M12287", 1) == [0]  # M0-M12287 on an R04CPU
            with pytest.raises(Exception, match="C056"):
                mc.batchread_bitunits("M12288", 1)
        finally:
            mc.close()
    finally:
        controller.shutdown()


def test_unknown_cpu_model_is_rejected():
    with pytest.raises(ValueError, match="unknown CPU model"):
        SLMPDevice(cpu="FX5U")
