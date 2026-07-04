def extract_jpeg(stego_path: str) -> bytes:
    jpg = jio.read(stego_path)
    flat = jpg.coef_arrays[0].reshape(-1)
    usable = np.where((flat != 0) & (flat != 1))[0]

    bits = [abs(flat[idx]) & 1 for idx in usable]

    def take_bytes(bit_list, n):
        out = bytearray()
        for i in range(n):
            byte = 0
            for b in bit_list[i*8:(i+1)*8]:
                byte = (byte << 1) | b
            out.append(byte)
        return bytes(out)

    header = take_bytes(bits, 8)  # MAGIC(4) + length(4)
    assert header[:4] == MAGIC, "ไม่พบข้อมูลที่ซ่อน หรือภาพเสียหาย"
    length = struct.unpack('>I', header[4:8])[0]

    total_bits = (8 + length) * 8
    payload_bits = bits[:total_bits]
    full = take_bytes(payload_bits, 8 + length)
    return full[8:]  # ตัด header ออก เหลือ cipher_blob