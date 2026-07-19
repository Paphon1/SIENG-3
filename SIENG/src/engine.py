import numpy as np
import jpeglib
from src.crypto import encrypt_blob, decrypt_blob
from src.payload import build_framed_payload, bytes_to_bits, bits_to_bytes, MAGIC, struct
from src.f5_core import f5_bit, hamming_hash

def run_embed(cover_path, stego_path, message, password, k=3, iters=200_000, verbose=True):
    cipher = encrypt_blob(message.encode('utf-8'), password, iters)
    payload = build_framed_payload(cipher)
    bits = list(bytes_to_bits(payload))
    
    n = (1 << k) - 1
    jpg = jpeglib.read_dct(cover_path)
    coeffs = jpg.Y
    
    flat = coeffs.flatten()
    usable_pos = np.where(flat != 0)[0]
    max_bits = (len(usable_pos) // n) * k
    
    if len(bits) > max_bits:
        raise ValueError(f"Payload target is too large: Needs {len(bits)} bits, max capacity ~{max_bits} bits")
        
    while len(bits) % k != 0:
        bits.append(0)
        
    msg_groups = [bits[i:i + k] for i in range(0, len(bits), k)]
    pos_iter = iter(usable_pos)
    changes, shrink_events = 0, 0
    
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
            raise ValueError("DCT Coefficients exhausted during embedding.")
            
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
                    raise ValueError("DCT Coefficients exhausted during matrix contraction (shrinkage).")
                continue
            break
            
    jpg.Y = flat.reshape(coeffs.shape)
    jpg.write_dct(stego_path)
    
    if verbose:
        eff = len(bits) / changes if changes else float('inf')
        print(f"[SUCCESS] Stego Image -> {stego_path}")
        print(f"          Efficiency  -> {eff:.2f} bits/change")

def run_extract(stego_path, password, k=3, iters=200_000):
    n = (1 << k) - 1
    jpg = jpeglib.read_dct(stego_path)
    flat = jpg.Y.flatten()
    usable_pos = np.where(flat != 0)[0]
    rec_bits = []
    pos_iter = iter(usable_pos)
    
    def read_group():
        grp = []
        while len(grp) < n:
            grp.append(int(flat[next(pos_iter)]))
        gb = [f5_bit(v) for v in grp]
        h = hamming_hash(gb, k)
        return [(h >> (k - 1 - j)) & 1 for j in range(k)]
        
    while len(rec_bits) < 64:
        rec_bits.extend(read_group())
        
    header = bits_to_bytes(rec_bits, 8)
    if header[:4] != MAGIC:
        raise ValueError("Invalid F5 signature. Incorrect password or corrupted file.")
        
    length = struct.unpack('>I', header[4:8])[0]
    need_bits = (8 + length) * 8
    while len(rec_bits) < need_bits:
        rec_bits.extend(read_group())
        
    full = bits_to_bytes(rec_bits, 8 + length)
    cipher = full[8:]
    return decrypt_blob(cipher, password, iters).decode('utf-8', errors='replace')