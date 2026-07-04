#!/usr/bin/env python3
"""
Sieng-F5 : Full F5 JPEG Steganography + AES-256-GCM (jpeglib Version)
====================================================================
ปรับปรุงให้รองรับ jpeglib สำหรับผู้ใช้ Windows ที่ติดปัญหาการคอมไพล์ C
"""

import os
import sys
import struct
import argparse
import numpy as np

try:
    import jpeglib
except ImportError:
    print("ERROR: ต้องติดตั้ง jpeglib ก่อน -> pip install jpeglib")
    sys.exit(1)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC = b'SF52'          # v2 สำหรับ jpeglib
PBKDF2_ITERS = 200_000
HAMMING_K = 3            # ฝัง 3 bits ต่อ 7 coefficients

# ===========================================================================
# ชั้นที่ 1 : Cryptography
# ===========================================================================
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERS)
    return kdf.derive(password.encode())

def encrypt(message: bytes, password: str) -> bytes:
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(derive_key(password, salt)).encrypt(nonce, message, None)
    return salt + nonce + ct

def decrypt(blob: bytes, password: str) -> bytes:
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    return AESGCM(derive_key(password, salt)).decrypt(nonce, ct, None)

# ===========================================================================
# ชั้นที่ 2 : Payload framing
# ===========================================================================
def build_payload(cipher_blob: bytes) -> bytes:
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

# ===========================================================================
# ชั้นที่ 3 : F5 LSB semantics
# ===========================================================================
def f5_bit(value: int) -> int:
    if value > 0:
        return value & 1
    else:
        return 1 - (abs(value) & 1)

def hamming_hash(group_bits, k):
    h = 0
    for i, b in enumerate(group_bits, start=1):
        if b:
            h ^= i
    return h

# ===========================================================================
# ชั้นที่ 4 : EMBED
# ===========================================================================
def embed(cover_path, stego_path, message, password, verbose=True):
    cipher = encrypt(message.encode(), password)
    payload = build_payload(cipher)
    bits = list(bytes_to_bits(payload))
    k = HAMMING_K
    n = (1 << k) - 1

    # อ่านค่าด้วย jpeglib
    jpg = jpeglib.read_dct(cover_path)
    coeffs = jpg.Y # ดึงค่า Luminance DCT coefficients (2D Array)
    
    # แปลงเป็นแบบมิติเดียวเพื่อประมวลผล stream
    flat = coeffs.flatten()
    usable_pos = np.where(flat != 0)[0]

    max_bits = (len(usable_pos) // n) * k
    if len(bits) > max_bits:
        raise ValueError(f"ข้อมูลใหญ่เกิน: ต้องการ {len(bits)} bits แต่ฝังได้ ~{max_bits} bits")

    while len(bits) % k != 0:
        bits.append(0)

    msg_groups = [bits[i:i + k] for i in range(0, len(bits), k)]
    pos_iter = iter(usable_pos)
    changes = 0
    shrink_events = 0

    def next_nonzero():
        while True:
            p = next(pos_iter)
            if flat[p] != 0:
                return p

    for m_bits in msg_groups:
        m = 0
        for b in m_bits:
            m = (m << 1) | b

        try:
            group_pos = [next_nonzero() for _ in range(n)]
        except StopIteration:
            raise ValueError("coefficient หมดก่อนฝังเสร็จ (ภาพเล็กไป)")

        while True:
            group_bits = [f5_bit(int(flat[p])) for p in group_pos]
            h = hamming_hash(group_bits, k)
            diff = h ^ m

            if diff == 0:
                break

            target = group_pos[diff - 1]
            v = int(flat[target])
            nv = v - 1 if v > 0 else v + 1
            flat[target] = nv
            changes += 1

            if nv == 0:
                shrink_events += 1
                group_pos.pop(diff - 1)
                try:
                    group_pos.append(next_nonzero())
                except StopIteration:
                    raise ValueError("coefficient หมดก่อนฝังเสร็จ (ภาพเล็กไป)")
                continue
            break

    # เขียนข้อมูลกลับเข้ารูปทรงเดิมและบันทึกด้วย jpeglib
    jpg.Y = flat.reshape(coeffs.shape)
    jpg.write_dct(stego_path)

    if verbose:
        eff = len(bits) / changes if changes else float('inf')
        print(f"[OK] ฝังสำเร็จ -> {stego_path}")
        print(f"     payload      = {len(payload)} bytes ({len(bits)} bits)")
        print(f"     coeff แก้ไข   = {changes} ตัว")
        print(f"     shrinkage    = {shrink_events} ครั้ง")
        print(f"     efficiency   = {eff:.2f} bits/change")

# ===========================================================================
# ชั้นที่ 5 : EXTRACT
# ===========================================================================
def extract(stego_path, password):
    k = HAMMING_K
    n = (1 << k) - 1

    jpg = jpeglib.read_dct(stego_path)
    flat = jpg.Y.flatten()
    usable_pos = np.where(flat != 0)[0]

    rec_bits = []
    pos_iter = iter(usable_pos)

    def read_group():
        grp = []
        while len(grp) < n:
            p = next(pos_iter)
            grp.append(int(flat[p]))
        gb = [f5_bit(v) for v in grp]
        h = hamming_hash(gb, k)
        return [(h >> (k - 1 - j)) & 1 for j in range(k)]

    while len(rec_bits) < 64:
        rec_bits.extend(read_group())

    header = bits_to_bytes(rec_bits, 8)
    if header[:4] != MAGIC:
        raise ValueError("ไม่พบข้อมูล F5 หรือภาพเสียหาย/ถูกแกะโครงสร้างมาผิด")
    length = struct.unpack('>I', header[4:8])[0]

    need_bits = (8 + length) * 8
    while len(rec_bits) < need_bits:
        rec_bits.extend(read_group())

    full = bits_to_bytes(rec_bits, 8 + length)
    cipher = full[8:]
    return decrypt(cipher, password).decode(errors='replace')

# ===========================================================================
# ชั้นที่ 6 : ANALYZE
# ===========================================================================
def analyze(cover_path):
    k = HAMMING_K
    n = (1 << k) - 1
    jpg = jpeglib.read_dct(cover_path)
    flat = jpg.Y.flatten()
    nonzero = int(np.sum(flat != 0))
    zeros = float(np.mean(flat == 0))
    cap_bits = (nonzero // n) * k
    cap_bytes = cap_bits // 8

    print(f"=== วิเคราะห์ {cover_path} (F5-jpeglib, k={k}) ===")
    print(f"DCT coeff ทั้งหมด   : {flat.size:,}")
    print(f"coeff ที่ไม่ใช่ 0    : {nonzero:,}")
    print(f"สัดส่วน 0           : {zeros:.1%}")
    print(f"ความจุจริงโดยประมาณ : ~{max(0, cap_bytes - 52):,} bytes")

# ===========================================================================
# CLI
# ===========================================================================
def main():
    p = argparse.ArgumentParser(description="Sieng-F5 jpeglib Version")
    sub = p.add_subparsers(dest='cmd', required=True)

    e = sub.add_parser('embed')
    e.add_argument('cover'); e.add_argument('stego')
    e.add_argument('-p', '--password', required=True)
    e.add_argument('-m', '--message', required=True)

    x = sub.add_parser('extract')
    x.add_argument('stego')
    x.add_argument('-p', '--password', required=True)

    a = sub.add_parser('analyze')
    a.add_argument('cover')

    args = p.parse_args()
    if args.cmd == 'embed':
        embed(args.cover, args.stego, args.message, args.password)
    elif args.cmd == 'extract':
        print(f"\n[ข้อความที่ถอดได้]\n{extract(args.stego, args.password)}")
    elif args.cmd == 'analyze':
        analyze(args.cover)

if __name__ == '__main__':
    main()