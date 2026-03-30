# SPDX-FileCopyrightText: © 2024 Tiny Tapeout
# SPDX-License-Identifier: Apache-2.0

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles, RisingEdge, FallingEdge

# Commands
CMD_NOP = 0b00
CMD_LOAD_KEY = 0b01
CMD_LOAD_PT = 0b10
CMD_START_READ = 0b11

# Status bit positions in uio_out
STATUS_BUSY = 2
STATUS_DONE = 3
STATUS_KEY_LOADED = 4
STATUS_PT_LOADED = 5


async def reset(dut):
    dut.ena.value = 1
    dut.ui_in.value = 0
    dut.uio_in.value = 0
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 5)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 1)


async def load_key(dut, key_int):
    """Load 10 key bytes MSB first."""
    key_bytes = key_int.to_bytes(10, byteorder="big")
    for b in key_bytes:
        dut.ui_in.value = b
        dut.uio_in.value = CMD_LOAD_KEY
        await RisingEdge(dut.clk)
    dut.uio_in.value = CMD_NOP
    await RisingEdge(dut.clk)


async def load_plaintext(dut, pt_int):
    """Load 8 plaintext bytes MSB first."""
    pt_bytes = pt_int.to_bytes(8, byteorder="big")
    for b in pt_bytes:
        dut.ui_in.value = b
        dut.uio_in.value = CMD_LOAD_PT
        await RisingEdge(dut.clk)
    dut.uio_in.value = CMD_NOP
    await RisingEdge(dut.clk)


async def start_and_wait(dut, timeout_cycles=100):
    """Send start command and wait for done."""
    dut.uio_in.value = CMD_START_READ
    await RisingEdge(dut.clk)
    dut.uio_in.value = CMD_NOP
    for _ in range(timeout_cycles):
        await RisingEdge(dut.clk)
        if (int(dut.uio_out.value) >> STATUS_DONE) & 1:
            return
    assert False, "Encryption timed out"


async def read_ciphertext(dut):
    """Read 8 ciphertext bytes. Byte 0 is already on uo_out after done."""
    await FallingEdge(dut.clk)
    ct_bytes = [int(dut.uo_out.value)]
    for _ in range(7):
        dut.uio_in.value = CMD_START_READ
        await RisingEdge(dut.clk)
        await FallingEdge(dut.clk)
        ct_bytes.append(int(dut.uo_out.value))
    # One more cmd=11 to reset to idle
    dut.uio_in.value = CMD_START_READ
    await RisingEdge(dut.clk)
    dut.uio_in.value = CMD_NOP
    await RisingEdge(dut.clk)
    return int.from_bytes(ct_bytes, byteorder="big")


async def encrypt(dut, key, plaintext):
    """Full encrypt cycle: load key, load PT, start, read CT."""
    await load_key(dut, key)
    await load_plaintext(dut, plaintext)
    await start_and_wait(dut)
    return await read_ciphertext(dut)


# ---------------------------------------------------------------------------
# Test: reset clears all status flags
# ---------------------------------------------------------------------------
@cocotb.test()
async def test_reset(dut):
    """After reset, all status flags should be cleared and output zero."""
    clock = Clock(dut.clk, 10, unit="us")
    cocotb.start_soon(clock.start())
    await reset(dut)

    status = int(dut.uio_out.value)
    assert (status >> STATUS_BUSY) & 1 == 0, "busy should be 0 after reset"
    assert (status >> STATUS_DONE) & 1 == 0, "done should be 0 after reset"
    assert (status >> STATUS_KEY_LOADED) & 1 == 0, "key_loaded should be 0 after reset"
    assert (status >> STATUS_PT_LOADED) & 1 == 0, "pt_loaded should be 0 after reset"


# ---------------------------------------------------------------------------
# Test: key_loaded flag asserts after 10 bytes
# ---------------------------------------------------------------------------
@cocotb.test()
async def test_key_loaded_flag(dut):
    """key_loaded should go high after exactly 10 key bytes are loaded."""
    clock = Clock(dut.clk, 10, unit="us")
    cocotb.start_soon(clock.start())
    await reset(dut)

    for i in range(10):
        assert (int(dut.uio_out.value) >> STATUS_KEY_LOADED) & 1 == 0, \
            f"key_loaded asserted too early at byte {i}"
        dut.ui_in.value = i
        dut.uio_in.value = CMD_LOAD_KEY
        await RisingEdge(dut.clk)

    dut.uio_in.value = CMD_NOP
    await RisingEdge(dut.clk)
    await FallingEdge(dut.clk)
    assert (int(dut.uio_out.value) >> STATUS_KEY_LOADED) & 1 == 1, \
        "key_loaded not asserted after 10 bytes"


# ---------------------------------------------------------------------------
# Test: pt_loaded flag asserts after 8 bytes
# ---------------------------------------------------------------------------
@cocotb.test()
async def test_pt_loaded_flag(dut):
    """pt_loaded should go high after exactly 8 plaintext bytes are loaded."""
    clock = Clock(dut.clk, 10, unit="us")
    cocotb.start_soon(clock.start())
    await reset(dut)

    for i in range(8):
        assert (int(dut.uio_out.value) >> STATUS_PT_LOADED) & 1 == 0, \
            f"pt_loaded asserted too early at byte {i}"
        dut.ui_in.value = i
        dut.uio_in.value = CMD_LOAD_PT
        await RisingEdge(dut.clk)

    dut.uio_in.value = CMD_NOP
    await RisingEdge(dut.clk)
    await FallingEdge(dut.clk)
    assert (int(dut.uio_out.value) >> STATUS_PT_LOADED) & 1 == 1, \
        "pt_loaded not asserted after 8 bytes"


# ---------------------------------------------------------------------------
# Test: extra key bytes are ignored after 10
# ---------------------------------------------------------------------------
@cocotb.test()
async def test_key_overflow_ignored(dut):
    """Loading more than 10 key bytes should not change state."""
    clock = Clock(dut.clk, 10, unit="us")
    cocotb.start_soon(clock.start())
    await reset(dut)

    await load_key(dut, 0x00000000000000000000)

    # Send extra key bytes
    for _ in range(5):
        dut.ui_in.value = 0xFF
        dut.uio_in.value = CMD_LOAD_KEY
        await RisingEdge(dut.clk)
    dut.uio_in.value = CMD_NOP
    await RisingEdge(dut.clk)

    # Should still show key_loaded
    await FallingEdge(dut.clk)
    assert (int(dut.uio_out.value) >> STATUS_KEY_LOADED) & 1 == 1


# ---------------------------------------------------------------------------
# Test: start without key/pt loaded does nothing
# ---------------------------------------------------------------------------
@cocotb.test()
async def test_start_without_data(dut):
    """Sending start command without key and PT loaded should not assert busy."""
    clock = Clock(dut.clk, 10, unit="us")
    cocotb.start_soon(clock.start())
    await reset(dut)

    dut.uio_in.value = CMD_START_READ
    await RisingEdge(dut.clk)
    await FallingEdge(dut.clk)
    assert (int(dut.uio_out.value) >> STATUS_BUSY) & 1 == 0, \
        "busy should not assert without data loaded"


# ---------------------------------------------------------------------------
# Test: busy flag during encryption
# ---------------------------------------------------------------------------
@cocotb.test()
async def test_busy_flag(dut):
    """busy should be high during encryption and clear when done."""
    clock = Clock(dut.clk, 10, unit="us")
    cocotb.start_soon(clock.start())
    await reset(dut)

    await load_key(dut, 0)
    await load_plaintext(dut, 0)

    # Start encryption
    dut.uio_in.value = CMD_START_READ
    await RisingEdge(dut.clk)
    dut.uio_in.value = CMD_NOP
    await RisingEdge(dut.clk)
    await FallingEdge(dut.clk)

    assert (int(dut.uio_out.value) >> STATUS_BUSY) & 1 == 1, \
        "busy should be high during encryption"

    # Wait for done
    for _ in range(100):
        await RisingEdge(dut.clk)
        if (int(dut.uio_out.value) >> STATUS_DONE) & 1:
            break

    assert (int(dut.uio_out.value) >> STATUS_BUSY) & 1 == 0, \
        "busy should be low after encryption completes"
    assert (int(dut.uio_out.value) >> STATUS_DONE) & 1 == 1, \
        "done should be high after encryption completes"


# ---------------------------------------------------------------------------
# Test: official test vector 1 — key=0, pt=0
# ---------------------------------------------------------------------------
@cocotb.test()
async def test_vector_1(dut):
    """PRESENT test vector: key=0, pt=0 -> ct=5579C1387B228445"""
    clock = Clock(dut.clk, 10, unit="us")
    cocotb.start_soon(clock.start())
    await reset(dut)

    ct = await encrypt(dut, 0x00000000000000000000, 0x0000000000000000)
    assert ct == 0x5579C1387B228445, f"Expected 5579C1387B228445, got {ct:016X}"


# ---------------------------------------------------------------------------
# Test: official test vector 2 — key=all-F, pt=0
# ---------------------------------------------------------------------------
@cocotb.test()
async def test_vector_2(dut):
    """PRESENT test vector: key=FF..FF, pt=0 -> ct=E72C46C0F5945049"""
    clock = Clock(dut.clk, 10, unit="us")
    cocotb.start_soon(clock.start())
    await reset(dut)

    ct = await encrypt(dut, 0xFFFFFFFFFFFFFFFFFFFF, 0x0000000000000000)
    assert ct == 0xE72C46C0F5945049, f"Expected E72C46C0F5945049, got {ct:016X}"


# ---------------------------------------------------------------------------
# Test: official test vector 3 — key=0, pt=all-F
# ---------------------------------------------------------------------------
@cocotb.test()
async def test_vector_3(dut):
    """PRESENT test vector: key=0, pt=FF..FF -> ct=A112FFC72F68417B"""
    clock = Clock(dut.clk, 10, unit="us")
    cocotb.start_soon(clock.start())
    await reset(dut)

    ct = await encrypt(dut, 0x00000000000000000000, 0xFFFFFFFFFFFFFFFF)
    assert ct == 0xA112FFC72F68417B, f"Expected A112FFC72F68417B, got {ct:016X}"


# ---------------------------------------------------------------------------
# Test: official test vector 4 — key=all-F, pt=all-F
# ---------------------------------------------------------------------------
@cocotb.test()
async def test_vector_4(dut):
    """PRESENT test vector: key=FF..FF, pt=FF..FF -> ct=3333DCD3213210D2"""
    clock = Clock(dut.clk, 10, unit="us")
    cocotb.start_soon(clock.start())
    await reset(dut)

    ct = await encrypt(dut, 0xFFFFFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)
    assert ct == 0x3333DCD3213210D2, f"Expected 3333DCD3213210D2, got {ct:016X}"


# ---------------------------------------------------------------------------
# Test: back-to-back encryptions
# ---------------------------------------------------------------------------
@cocotb.test()
async def test_back_to_back(dut):
    """Two consecutive encryptions with different keys should both succeed."""
    clock = Clock(dut.clk, 10, unit="us")
    cocotb.start_soon(clock.start())
    await reset(dut)

    ct1 = await encrypt(dut, 0x00000000000000000000, 0x0000000000000000)
    assert ct1 == 0x5579C1387B228445, f"First encryption failed: {ct1:016X}"

    ct2 = await encrypt(dut, 0xFFFFFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)
    assert ct2 == 0x3333DCD3213210D2, f"Second encryption failed: {ct2:016X}"


# ---------------------------------------------------------------------------
# Test: all four vectors sequentially without reset between them
# ---------------------------------------------------------------------------
@cocotb.test()
async def test_all_vectors_sequential(dut):
    """Run all 4 test vectors back-to-back without resetting between them."""
    clock = Clock(dut.clk, 10, unit="us")
    cocotb.start_soon(clock.start())
    await reset(dut)

    vectors = [
        (0x00000000000000000000, 0x0000000000000000, 0x5579C1387B228445),
        (0xFFFFFFFFFFFFFFFFFFFF, 0x0000000000000000, 0xE72C46C0F5945049),
        (0x00000000000000000000, 0xFFFFFFFFFFFFFFFF, 0xA112FFC72F68417B),
        (0xFFFFFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x3333DCD3213210D2),
    ]

    for i, (key, pt, expected) in enumerate(vectors):
        ct = await encrypt(dut, key, pt)
        assert ct == expected, \
            f"Vector {i+1} failed: got {ct:016X}, expected {expected:016X}"


# ---------------------------------------------------------------------------
# Test: NOP command doesn't change state
# ---------------------------------------------------------------------------
@cocotb.test()
async def test_nop_no_effect(dut):
    """Sending NOP commands should not affect key or PT counters."""
    clock = Clock(dut.clk, 10, unit="us")
    cocotb.start_soon(clock.start())
    await reset(dut)

    # Send many NOPs
    for _ in range(20):
        dut.uio_in.value = CMD_NOP
        await RisingEdge(dut.clk)

    await FallingEdge(dut.clk)
    status = int(dut.uio_out.value)
    assert (status >> STATUS_KEY_LOADED) & 1 == 0, "key_loaded should still be 0"
    assert (status >> STATUS_PT_LOADED) & 1 == 0, "pt_loaded should still be 0"
    assert (status >> STATUS_BUSY) & 1 == 0, "busy should still be 0"
    assert (status >> STATUS_DONE) & 1 == 0, "done should still be 0"


# ---------------------------------------------------------------------------
# Test: uio_oe is correctly configured
# ---------------------------------------------------------------------------
@cocotb.test()
async def test_uio_oe(dut):
    """uio_oe should be 0b11111100 — bits [1:0] input, [7:2] output."""
    clock = Clock(dut.clk, 10, unit="us")
    cocotb.start_soon(clock.start())
    await reset(dut)

    assert int(dut.uio_oe.value) == 0b11111100, \
        f"uio_oe should be 0xFC, got {int(dut.uio_oe.value):#04x}"
