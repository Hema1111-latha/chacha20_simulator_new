"""
chacha20.py - Pure-Python implementation of the ChaCha20 stream cipher (RFC 8439).

Educational implementation: it also records every intermediate state so the
web interface can show the algorithm step by step.
"""
import struct

MASK32 = 0xFFFFFFFF
# "expand 32-byte k" as four little-endian 32-bit words
CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def rotl32(value: int, shift: int) -> int:
    """Rotate a 32-bit integer left by `shift` bits."""
    return ((value << shift) & MASK32) | (value >> (32 - shift))


def quarter_round(s: list, a: int, b: int, c: int, d: int) -> None:
    """ChaCha quarter round, operating in place on state list `s`."""
    s[a] = (s[a] + s[b]) & MASK32
    s[d] ^= s[a]
    s[d] = rotl32(s[d], 16)

    s[c] = (s[c] + s[d]) & MASK32
    s[b] ^= s[c]
    s[b] = rotl32(s[b], 12)

    s[a] = (s[a] + s[b]) & MASK32
    s[d] ^= s[a]
    s[d] = rotl32(s[d], 8)

    s[c] = (s[c] + s[d]) & MASK32
    s[b] ^= s[c]
    s[b] = rotl32(s[b], 7)


def validate_inputs(key: bytes, nonce: bytes, counter: int) -> None:
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes (64 hex characters).")
    if len(nonce) != 12:
        raise ValueError("Nonce must be exactly 12 bytes (24 hex characters).")
    if not 0 <= counter <= MASK32:
        raise ValueError("Counter must be between 0 and 4294967295.")


def build_state(key: bytes, nonce: bytes, counter: int) -> list:
    """Create the initial 4x4 (16-word) ChaCha20 state."""
    validate_inputs(key, nonce, counter)
    return (
        list(CONSTANTS)
        + list(struct.unpack("<8I", key))
        + [counter]
        + list(struct.unpack("<3I", nonce))
    )


def chacha20_block(key: bytes, nonce: bytes, counter: int, trace: bool = False):
    """
    Generate one 64-byte keystream block.
    Returns (keystream_block, trace_dict_or_None).
    """
    initial = build_state(key, nonce, counter)
    working = initial[:]
    rounds = []

    for _ in range(10):  # 10 double rounds = 20 rounds
        # Column round
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        if trace:
            rounds.append(working[:])
        # Diagonal round
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)
        if trace:
            rounds.append(working[:])

    after_rounds = working[:]
    final = [(w + i) & MASK32 for w, i in zip(working, initial)]
    keystream = struct.pack("<16I", *final)

    info = None
    if trace:
        info = {
            "initial": initial,
            "rounds": rounds,          # 20 states, one per round
            "after_rounds": after_rounds,
            "final": final,
            "keystream": keystream,
        }
    return keystream, info


def chacha20_crypt(key: bytes, nonce: bytes, data: bytes, counter: int = 1) -> bytes:
    """Encrypt or decrypt `data` (the operation is identical: XOR with keystream)."""
    validate_inputs(key, nonce, counter)
    blocks_needed = (len(data) + 63) // 64
    if counter + blocks_needed > MASK32 + 1:
        raise ValueError("Message too long for this starting counter.")

    out = bytearray()
    for i in range(blocks_needed):
        block, _ = chacha20_block(key, nonce, counter + i)
        chunk = data[i * 64:(i + 1) * 64]
        out.extend(b ^ k for b, k in zip(chunk, block))
    return bytes(out)
