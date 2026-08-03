#!/usr/bin/env python3
#
# Rainbow Crackalack: tests/netntlmv1_ref.py
#
# An independent reference implementation of the Net-NTLMv1 rainbow-chain
# primitives.  It deliberately shares no code with the C host or the OpenCL
# kernels so that it can act as an oracle for both.
#
# A Net-NTLMv1 "plaintext" is a raw 7-byte DES key (one third of an NTLM hash)
# and its "hash" is DES(expand(key), CHALLENGE), where CHALLENGE is the fixed
# 1122334455667788 server challenge.  See CL/rt.cl and cpu_rt_functions.c.
#
# Pure standard library on purpose: no pycryptodome, no openssl, so CI needs no
# crypto dependency and cannot be broken by an openssl provider change.
#

CHALLENGE = bytes.fromhex("1122334455667788")

# --- DES ---------------------------------------------------------------------

_IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]
_FP = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
]
_E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
]
_P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]
_PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
]
_PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
]
_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
_SBOX = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]


def _bits(data):
    out = []
    for byte in data:
        for i in range(7, -1, -1):
            out.append((byte >> i) & 1)
    return out


def _unbits(bits):
    out = bytearray(len(bits) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i // 8] |= 1 << (7 - (i % 8))
    return bytes(out)


def _permute(bits, table):
    return [bits[i - 1] for i in table]


def _subkeys(key8):
    kb = _permute(_bits(key8), _PC1)
    c, d = kb[:28], kb[28:]
    keys = []
    for shift in _SHIFTS:
        c = c[shift:] + c[:shift]
        d = d[shift:] + d[:shift]
        keys.append(_permute(c + d, _PC2))
    return keys


def des_encrypt_block(key8, block8):
    """Single-block DES-ECB encryption.  Key parity bits are ignored, as in DES."""
    assert len(key8) == 8 and len(block8) == 8
    keys = _subkeys(key8)
    bits = _permute(_bits(block8), _IP)
    left, right = bits[:32], bits[32:]
    for rk in keys:
        x = [a ^ b for a, b in zip(_permute(right, _E), rk)]
        sout = []
        for i in range(8):
            chunk = x[i * 6:(i + 1) * 6]
            row = (chunk[0] << 1) | chunk[5]
            col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
            val = _SBOX[i][row * 16 + col]
            sout += [(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1]
        f = _permute(sout, _P)
        left, right = right, [a ^ b for a, b in zip(left, f)]
    return _unbits(_permute(right + left, _FP))


# --- Net-NTLMv1 rainbow-chain primitives -------------------------------------

def setup_des_key(key7):
    """Expand a 7-byte key to 8 bytes with zeroed parity bits.

    Mirrors setup_des_key() in cpu_rt_functions.c.
    """
    assert len(key7) == 7
    k = key7
    return bytes([
        ((k[0] >> 1) & 0x7F) << 1,
        (((k[0] & 0x01) << 6) | ((k[1] >> 2) & 0x3F)) << 1,
        (((k[1] & 0x03) << 5) | ((k[2] >> 3) & 0x1F)) << 1,
        (((k[2] & 0x07) << 4) | ((k[3] >> 4) & 0x0F)) << 1,
        (((k[3] & 0x0F) << 3) | ((k[4] >> 5) & 0x07)) << 1,
        (((k[4] & 0x1F) << 2) | ((k[5] >> 6) & 0x03)) << 1,
        (((k[5] & 0x3F) << 1) | ((k[6] >> 7) & 0x01)) << 1,
        (k[6] & 0x7F) << 1,
    ])


def netntlmv1_hash(key7):
    """The rainbow-table 'hash': DES(expand(key7), 1122334455667788)."""
    return des_encrypt_block(setup_des_key(key7), CHALLENGE)


PLAINTEXT_SPACE_TOTAL = 256 ** 7  # charset 'byte', plaintext length 7-7


def index_to_plaintext(index):
    """charset 'byte' is the identity map 0x00..0xff, so this is base-256 big-endian."""
    return (index % PLAINTEXT_SPACE_TOTAL).to_bytes(7, "big")


def hash_to_index(hash8, reduction_offset, pos, space_total=PLAINTEXT_SPACE_TOTAL):
    """Mirrors hash_to_index() in CL/rt.cl: little-endian load of the 8 hash bytes."""
    return (int.from_bytes(hash8[:8], "little") + reduction_offset + pos) % space_total


def table_index_to_reduction_offset(table_index):
    """Mirrors TABLE_INDEX_TO_REDUCTION_OFFSET in shared.h."""
    return table_index * 65536


def walk_chain(start_index, chain_len, reduction_offset=0, stop_at=None):
    """Walk a rainbow chain from start_index.

    Mirrors generate_rainbow_chain() in CL/rt.cl, which iterates pos over
    [0, chain_len - 1).  Returns (end_index, plaintext_at_stop, hash_at_stop);
    the latter two are None unless stop_at names a position.
    """
    index = start_index
    pt_at = h_at = None
    for pos in range(0, chain_len - 1):
        pt = index_to_plaintext(index)
        h = netntlmv1_hash(pt)
        index = hash_to_index(h, reduction_offset, pos)
        if stop_at is not None and pos == stop_at:
            pt_at, h_at = pt, h
    return index, pt_at, h_at


def self_test():
    """Anchor the DES implementation on published test vectors."""
    # Classic all-zero-key DES vector; also shows parity bits are ignored.
    assert des_encrypt_block(bytes.fromhex("0101010101010101"),
                             bytes.fromhex("0000000000000000")).hex() == "8ca64de9c1b123a7"
    assert des_encrypt_block(bytes.fromhex("0000000000000000"),
                             bytes.fromhex("0000000000000000")).hex() == "8ca64de9c1b123a7"
    # The fixed challenge under an all-zero key (cross-checked against
    # `openssl enc -des-ecb -provider legacy`).
    assert netntlmv1_hash(bytes(7)).hex() == "cd72dfc6e6d040a4"
    # Ground truth from the Mandiant/Google Cloud Net-NTLMv1 deprecation writeup:
    # the NTLM hash 9e969e23a39134884488e0247650fffc under challenge
    # 1122334455667788 produces the response 59b8beff...cec31640e20cbfca.
    assert netntlmv1_hash(bytes.fromhex("9e969e23a39134")).hex() == "59b8beffd0c2aec5"
    assert netntlmv1_hash(bytes.fromhex("884488e0247650")).hex() == "a9d83c6ca210be62"
    assert netntlmv1_hash(bytes.fromhex("fffc0000000000")).hex() == "cec31640e20cbfca"


if __name__ == "__main__":
    self_test()
    print("netntlmv1_ref self-test: OK")
