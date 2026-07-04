def analyze_cover(cover_path):
    jpg = jio.read(cover_path)
    flat = jpg.coef_arrays[0].reshape(-1)
    usable = int(np.sum((flat != 0) & (flat != 1)))
    capacity_bytes = usable // 8
    zeros_ratio = np.mean(flat == 0)
    return {
        "capacity_bytes": capacity_bytes,
        "usable_coeffs": usable,
        "zeros_ratio": float(zeros_ratio),
    }