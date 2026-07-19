def f5_bit(value: int) -> int:
    return value & 1 if value > 0 else 1 - (abs(value) & 1)

def hamming_hash(group_bits, k: int) -> int:
    h = 0
    for i, b in enumerate(group_bits, start=1):
        if b:
            h ^= i
    return h