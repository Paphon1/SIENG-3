import struct

MAGIC = b'SF52'

def build_framed_payload(cipher_blob: bytes) -> bytes:
    return MAGIC + struct.pack('>I', len(cipher_blob)) + cipher_blob

def bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1

def bits_to_bytes(bits, n_bytes):
    out = bytearray()
    for i in range(n_bytes):
        v = 0
        for b in bits[i * 8:(i + 1) * 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)