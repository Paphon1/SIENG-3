#!/usr/bin/env python3
"""
Sieng - JPEG Steganography + Cryptography (DCT-domain, F5-style)
================================================================
ฝังข้อความลับที่เข้ารหัสแล้วลงใน DCT coefficients ของภาพ JPEG
รองรับ JPEG จริง (ไม่หายตอนบันทึก) และต้าน statistical steganalysis

การใช้งาน:
    python sieng.py embed   cover.jpg stego.jpg -p "password" -m "ข้อความลับ"
    python sieng.py extract stego.jpg          -p "password"
    python sieng.py analyze cover.jpg
"""

import os
import sys
import struct
import argparse

import numpy as np

try:
    import jpegio as jio
except ImportError:
    print("ERROR: ต้องติดตั้ง jpegio ก่อน  ->  pip install jpegio")
    sys.exit(1)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC = b'SNG1'            # ระบุว่าไฟล์นี้มีข้อมูลของเรา
PBKDF2_ITERS = 200_000


# ---------------------------------------------------------------------------
# ชั้นที่ 1: Cryptography (AES-256-GCM + PBKDF2)
# ---------------------------------------------------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=PBKDF2_ITERS)
    return kdf.derive(password.encode())


def encrypt(message: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    ct = AESGCM(key).encrypt(nonce, message, None)
    return salt + nonce + ct        # 16 + 12 + (len + 16 tag)


def decrypt(blob: bytes, password: str) -> bytes:
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    key = derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, ct, None)


# ---------------------------------------------------------------------------
# ชั้นที่ 2: Payload framing (MAGIC + length + ciphertext)
# ---------------------------------------------------------------------------
def build_payload(cipher_blob: bytes) -> bytes:
    length = struct.pack('>I', len(cipher_blob))
    return MAGIC + length + cipher_blob


def bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def bits_to_bytes(bits, n_bytes):
    out = bytearray()
    for i in range(n_bytes):
        byte = 0
        for b in bits[i * 8:(i + 1) * 8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)


# ---------------------------------------------------------------------------
# ชั้นที่ 3: DCT-domain embedding (F5-style, LSB++)
# ---------------------------------------------------------------------------
def _usable_indices(flat):
    """เลือก coefficient ที่ != 0 และ != 1 (เลี่ยง 0 ที่มีเยอะ)"""
    return np.where((flat != 0) & (flat != 1))[0]


def embed(cover_path, stego_path, message, password):
    cipher = encrypt(message.encode(), password)
    payload = build_payload(cipher)
    bits = list(bytes_to_bits(payload))

    jpg = jio.read(cover_path)
    coeffs = jpg.coef_arrays[0]          # channel luminance (Y)
    flat = coeffs.reshape(-1)
    usable = _usable_indices(flat)

    if len(bits) > len(usable):
        raise ValueError(
            f"ข้อมูลใหญ่เกินไป: ต้องการ {len(bits)} bits "
            f"แต่ภาพรับได้ {len(usable)} bits")

    for bit, idx in zip(bits, usable):
        val = int(flat[idx])
        if (abs(val) & 1) != bit:
            # F5: ลด magnitude เข้าหา 0 (histogram เพี้ยนน้อย)
            flat[idx] = val - 1 if val > 0 else val + 1

    jpg.coef_arrays[0] = flat.reshape(coeffs.shape)
    jio.write(jpg, stego_path)
    print(f"[OK] ฝังสำเร็จ: {len(payload)} bytes -> {stego_path}")


def extract(stego_path, password):
    jpg = jio.read(stego_path)
    flat = jpg.coef_arrays[0].reshape(-1)
    usable = _usable_indices(flat)

    bits = [abs(int(flat[idx])) & 1 for idx in usable]

    header = bits_to_bytes(bits, 8)      # MAGIC(4) + length(4)
    if header[:4] != MAGIC:
        raise ValueError("ไม่พบข้อมูลที่ซ่อน หรือภาพเสียหาย")

    length = struct.unpack('>I', header[4:8])[0]
    full = bits_to_bytes(bits, 8 + length)
    cipher = full[8:]

    message = decrypt(cipher, password)
    return message.decode(errors='replace')


# ---------------------------------------------------------------------------
# ชั้นที่ 4: Analyze (ประเมิน capacity + ความเสี่ยง)
# ---------------------------------------------------------------------------
def analyze(cover_path):
    jpg = jio.read(cover_path)
    flat = jpg.coef_arrays[0].reshape(-1)
    usable = int(np.sum((flat != 0) & (flat != 1)))
    zeros = float(np.mean(flat == 0))
    cap = usable // 8

    print(f"=== วิเคราะห์ {cover_path} ===")
    print(f"DCT coefficients ทั้งหมด : {flat.size:,}")
    print(f"coefficient ที่ใช้ได้     : {usable:,}")
    print(f"ความจุสูงสุด (payload)   : {cap:,} bytes (~{cap//1024} KB)")
    print(f"สัดส่วน coeff ที่เป็น 0    : {zeros:.1%}")

    if zeros > 0.90:
        print("[!] ภาพเรียบมาก เสี่ยงถูกตรวจจับ + capacity ต่ำ "
              "-> ควรใช้ภาพที่มี texture มากกว่า")
    elif zeros > 0.75:
        print("[~] ภาพพอใช้ได้ แต่ควรฝังไม่เกิน 50% ของ capacity")
    else:
        print("[OK] ภาพเหมาะกับการฝัง texture เยอะดี")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description="Sieng JPEG steganography")
    sub = p.add_subparsers(dest='cmd', required=True)

    e = sub.add_parser('embed', help='ฝังข้อความ')
    e.add_argument('cover'); e.add_argument('stego')
    e.add_argument('-p', '--password', required=True)
    e.add_argument('-m', '--message', required=True)

    x = sub.add_parser('extract', help='ถอดข้อความ')
    x.add_argument('stego')
    x.add_argument('-p', '--password', required=True)

    a = sub.add_parser('analyze', help='วิเคราะห์ภาพ')
    a.add_argument('cover')

    args = p.parse_args()

    if args.cmd == 'embed':
        embed(args.cover, args.stego, args.message, args.password)
    elif args.cmd == 'extract':
        msg = extract(args.stego, args.password)
        print(f"\n[ข้อความที่ถอดได้]\n{msg}")
    elif args.cmd == 'analyze':
        analyze(args.cover)


if __name__ == '__main__':
    main()