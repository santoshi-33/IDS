#!/usr/bin/env python3
"""
Generate synthetic NSL-KDD-shaped CSVs for load testing (KB, MB, multi-GB).
Same columns as data/train.csv (if present) or a built-in schema.

  python scripts/generate_test_datasets.py
  python scripts/generate_test_datasets.py --skip-2gb
  python scripts/generate_test_datasets.py --target-gb 1.0
  python scripts/generate_test_datasets.py --out-dir data/test_cases --no-legacy-synth-names \
      --prefix test --mb-target 200 --target-gb 1 --skip-small --skip-large
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import List

import numpy as np

# Columns must match training CSV (no attack_type; label is last)
COLUMNS: List[str] = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "label",
]

PROTO = ["tcp", "udp", "icmp"]
SERVICE = [
    "http", "https", "ftp_data", "smtp", "private", "other", "domain", "ecr_i", "auth",
]
FLAGS = ["SF", "S0", "REJ", "RSTO", "SH", "RSTR", "S1", "S2", "S3", "OTH"]


def _random_rows(rng: np.random.Generator, n: int) -> List[List[object]]:
    rows: List[List[object]] = []
    for _ in range(n):
        proto = str(rng.choice(PROTO))
        service = str(rng.choice(SERVICE))
        flag = str(rng.choice(FLAGS))
        src_b = int(rng.integers(0, 100_000))
        dst_b = int(rng.integers(0, 1_000_000))
        land = int(rng.integers(0, 2))
        wrong_fragment = int(rng.integers(0, 4))
        urgent = int(rng.integers(0, 2))
        hot = int(rng.integers(0, 20))
        num_failed = int(rng.integers(0, 5))
        logged_in = int(rng.integers(0, 2))
        num_comp = int(rng.integers(0, 10))
        root_sh = int(rng.integers(0, 2))
        su_a = int(rng.integers(0, 2))
        num_root = int(rng.integers(0, 5))
        nfc = int(rng.integers(0, 10))
        nshells = int(rng.integers(0, 5))
        naf = int(rng.integers(0, 20))
        noc = 0
        is_host = int(rng.integers(0, 2))
        is_guest = int(rng.integers(0, 2))
        count = int(rng.integers(0, 500))
        srv_count = int(rng.integers(0, 500))
        rate_block_a = [float(rng.random()) for _ in range(7)]
        dst_hc = int(rng.integers(0, 300))
        dst_hsvc = int(rng.integers(0, 300))
        rate_block_b = [float(rng.random()) for _ in range(8)]
        label = "normal" if rng.random() < 0.5 else "attack"
        row = [
            int(rng.integers(0, 30_000)),
            proto,
            service,
            flag,
            src_b,
            dst_b,
            land,
            wrong_fragment,
            urgent,
            hot,
            num_failed,
            logged_in,
            num_comp,
            root_sh,
            su_a,
            num_root,
            nfc,
            nshells,
            naf,
            noc,
            is_host,
            is_guest,
            count,
            srv_count,
        ]
        row.extend(rate_block_a)
        row.extend([dst_hc, dst_hsvc])
        row.extend(rate_block_b)
        row.append(label)
        rows.append(row)
    return rows


def write_csv(path: Path, n_rows: int, rng: np.random.Generator) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(COLUMNS)
        chunk = 5_000
        left = n_rows
        while left > 0:
            take = min(chunk, left)
            for row in _random_rows(rng, take):
                w.writerow(row)
            left -= take


def write_until_size(
    path: Path, target_bytes: int, rng: np.random.Generator, chunk: int = 5_000
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(COLUMNS)
        f.flush()
        while f.tell() < target_bytes:
            for row in _random_rows(rng, chunk):
                w.writerow(row)
            f.flush()
            total = f.tell()
            gb = total / (1024**3)
            if gb >= 0.1:
                print(f"  ... {path.name} ~{gb:.2f} GB", flush=True)
            else:
                print(f"  ... {path.name} ~{total / (1024**2):.1f} MB", flush=True)


def _default_paths(out: Path, prefix: str, mb_target: float, target_gb: float) -> tuple[Path, Path, Path]:
    mb_name = f"{int(mb_target)}mb" if float(mb_target).is_integer() else str(mb_target).replace(".", "_")
    gb_name = f"{int(target_gb)}gb" if float(target_gb).is_integer() else str(target_gb).replace(".", "_")
    return (
        out / f"{prefix}_small.csv",
        out / f"{prefix}_{mb_name}.csv",
        out / f"{prefix}_{gb_name}.csv",
    )


def _legacy_synth_paths(out: Path) -> tuple[Path, Path, Path]:
    """Names used when outputting to `data/synth/` (backward compatible)."""
    return (
        out / "synth_small_kb.csv",
        out / "synth_medium_mb.csv",
        out / "synth_large_2gb.csv",
    )


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--out-dir", default="data/synth", help="Output directory")
    p.add_argument(
        "--prefix",
        default="test",
        help="File name prefix when not using legacy synth/ names, e.g. test -> test_small.csv, test_200mb.csv",
    )
    p.add_argument(
        "--use-legacy-synth-names",
        action="store_true",
        help="Use synth_small_kb.csv / synth_medium_mb.csv / synth_large_2gb.csv (on by default for --out-dir data/synth).",
    )
    p.add_argument(
        "--no-legacy-synth-names",
        action="store_true",
        help="Always use --prefix-based file names, even for data/synth.",
    )
    p.add_argument(
        "--kb-rows",
        type=int,
        default=50,
        help="Rows for tiny file (tens of KB; increase for larger small test file)",
    )
    p.add_argument("--mb-target", type=float, default=30.0, help="Target size for MB file")
    p.add_argument("--target-gb", type=float, default=2.0, help="Target size for large file (GB)")
    p.add_argument("--skip-small", action="store_true", help="Do not generate the small (KB) file")
    p.add_argument("--skip-medium", action="store_true", help="Do not generate the medium (MB) file")
    p.add_argument("--skip-large", action="store_true", help="Do not generate the large (GB) file")
    p.add_argument(
        "--skip-2gb",
        action="store_true",
        help="Alias for --skip-large (kept for backward compatibility)",
    )
    args = p.parse_args()

    if args.skip_2gb:
        args.skip_large = True  # type: ignore[misc]

    out = Path(args.out_dir)
    rng = np.random.default_rng(42)

    out_n = out.as_posix().rstrip("/").lower()
    default_legacy = out_n.endswith("data/synth") and not args.no_legacy_synth_names
    use_legacy = (args.use_legacy_synth_names or default_legacy) and not args.no_legacy_synth_names
    if use_legacy:
        kb_path, mb_path, gb_path = _legacy_synth_paths(out)
    else:
        kb_path, mb_path, gb_path = _default_paths(out, args.prefix, args.mb_target, args.target_gb)

    if not args.skip_small:
        print("Small (KB):", kb_path, f"rows={args.kb_rows}")
        write_csv(kb_path, args.kb_rows, rng)
        print("  size:", kb_path.stat().st_size, "bytes")
    else:
        print("Skipped small file (--skip-small).")

    if not args.skip_medium:
        mb_bytes = int(args.mb_target * 1024 * 1024)
        print("Medium (MB):", mb_path, f"~{args.mb_target} MB (writes until size >= target)")
        mb_path.parent.mkdir(parents=True, exist_ok=True)
        with mb_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(COLUMNS)
            f.flush()
            while f.tell() < mb_bytes:
                for row in _random_rows(rng, 2_000):
                    w.writerow(row)
                f.flush()
        print("  size:", mb_path.stat().st_size, "bytes")
    else:
        print("Skipped medium file (--skip-medium).")

    if args.skip_large:
        print("Skipped large file (--skip-large / --skip-2gb).")
        return

    target = int(args.target_gb * 1024**3)
    print("Large:", gb_path, f"~{args.target_gb} GB (this may take a long time, needs free disk).")
    write_until_size(gb_path, target, rng)
    print("  size:", gb_path.stat().st_size, "bytes")


if __name__ == "__main__":
    main()
