MAGIC = b'SNG1'  # 4 bytes ระบุว่าเป็นไฟล์ของเรา

def build_payload(cipher_blob: bytes) -> bytes:
    length = struct.pack('>I', len(cipher_blob))  # 4 bytes big-endian
    return MAGIC + length + cipher_blob

def bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1