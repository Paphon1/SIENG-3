import jpegio as jio
import numpy as np

def embed_jpeg(cover_path: str, stego_path: str, payload: bytes):
    jpg = jio.read(cover_path)
    coeffs = jpg.coef_arrays[0]   # DCT coeffs ของ luminance channel

    bits = list(bytes_to_bits(payload))
    flat = coeffs.reshape(-1)

    # เลือกเฉพาะ coefficient ที่ != 0 และ != 1 (หลัก F5/JSteg)
    usable = np.where((flat != 0) & (flat != 1))[0]

    if len(bits) > len(usable):
        raise ValueError("ข้อมูลใหญ่เกินกว่าที่ภาพจะรับได้")

    for bit, idx in zip(bits, usable):
        val = flat[idx]
        # ปรับ LSB ของ coefficient ให้ตรงกับ bit
        if (abs(val) & 1) != bit:
            # ลด magnitude ลง 1 (แนวทาง F5 ลดค่าเข้าหา 0)
            flat[idx] = val - 1 if val > 0 else val + 1

    jpg.coef_arrays[0] = flat.reshape(coeffs.shape)
    jio.write(jpg, stego_path)