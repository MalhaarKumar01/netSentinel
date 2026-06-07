#!/usr/bin/env python3
"""Train a NetSentinel Isolation Forest on the CICIDS2017 dataset.

Usage examples
--------------
# Single file
python scripts/train_model.py data/Friday-WorkingHours.pcap_ISCX.csv

# All CICIDS2017 CSVs in a directory
python scripts/train_model.py data/*.csv

# Tune contamination and output path
python scripts/train_model.py data/ --contamination 0.05 --output models/v2.joblib

# Skip evaluation (faster, no labels needed)
python scripts/train_model.py data/ --no-eval
"""
from __future__ import annotations

import argparse
import math
import sys
import warnings
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

from netsentinel.ml import FEATURE_COLUMNS
from netsentinel.security import stable_sha256

# ---------------------------------------------------------------------------
# CICIDS2017 column mapping
#   Keys are stripped column names as they appear in CICFlowMeter CSVs.
#   Values are internal staging names (prefixed with _) or final feature names.
# ---------------------------------------------------------------------------
_CICIDS_MAP: dict[str, str] = {
    "Total Fwd Packets": "_fwd_pkts",
    "Total Backward Packets": "_bwd_pkts",
    "Total Length of Fwd Packets": "_fwd_bytes",
    "Total Length of Bwd Packets": "_bwd_bytes",
    "Flow Duration": "_duration_us",       # microseconds in CICIDS2017
    "Packet Length Mean": "_pkt_len_mean",
    "Flow Bytes/s": "bytes_per_sec",
    "Flow Packets/s": "packets_per_sec",
    "SYN Flag Count": "syn_count",
    "ACK Flag Count": "ack_count",
    "Label": "_label",
    # Optional – used to compute per-source aggregated features
    "Source IP": "_src_ip",
    "Destination IP": "_dst_ip",
    "Destination Port": "_dst_port",
}

_BENIGN_LABEL = "BENIGN"


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _resolve_paths(raw: list[str]) -> list[Path]:
    paths: list[Path] = []
    for token in raw:
        p = Path(token)
        if p.is_dir():
            paths.extend(sorted(p.glob("*.csv")))
        elif "*" in token or "?" in token:
            from glob import glob
            paths.extend(Path(g) for g in sorted(glob(token)))
        elif p.exists():
            paths.append(p)
        else:
            print(f"[WARN] path not found, skipping: {p}", file=sys.stderr)
    if not paths:
        raise FileNotFoundError("No CSV files resolved from the given paths.")
    return paths


def _load_csvs(paths: list[Path]) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    for path in paths:
        print(f"  loading {path.name} …", flush=True)
        df = pd.read_csv(path, low_memory=False)
        df.columns = [c.strip() for c in df.columns]  # strip leading/trailing spaces
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


# ---------------------------------------------------------------------------
# Column mapping + feature derivation
# ---------------------------------------------------------------------------

def _map_columns(df: pd.DataFrame) -> pd.DataFrame:
    rename: dict[str, str] = {}
    for cicids_name, internal_name in _CICIDS_MAP.items():
        if cicids_name in df.columns:
            rename[cicids_name] = internal_name
    df = df.rename(columns=rename)

    missing = [k for k, v in _CICIDS_MAP.items() if v not in ("_src_ip", "_dst_ip", "_dst_port", "_label") and v not in df.columns]
    if missing:
        raise ValueError(
            f"Dataset is missing required CICIDS2017 columns after mapping:\n  {missing}\n"
            "Check that the CSV was exported by CICFlowMeter and contains the expected headers."
        )
    return df


def _derive_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    df["packet_count"] = df["_fwd_pkts"] + df["_bwd_pkts"]
    df["byte_count"] = df["_fwd_bytes"] + df["_bwd_bytes"]
    # CICIDS2017 stores duration in microseconds; clip to ≥ 1 µs before converting
    df["flow_duration"] = (df["_duration_us"].clip(lower=1) / 1_000_000).clip(lower=1e-6)
    df["avg_packet_size"] = df["byte_count"] / df["packet_count"].clip(lower=1)

    # packets_per_sec / bytes_per_sec: use dataset values when present and valid,
    # otherwise recalculate from counts and duration.
    if "packets_per_sec" in df.columns:
        bad = (~df["packets_per_sec"].between(0, 1e9, inclusive="both"))
        df.loc[bad, "packets_per_sec"] = df.loc[bad, "packet_count"] / df.loc[bad, "flow_duration"]
    else:
        df["packets_per_sec"] = df["packet_count"] / df["flow_duration"]

    if "bytes_per_sec" in df.columns:
        bad = (~df["bytes_per_sec"].between(0, 1e12, inclusive="both"))
        df.loc[bad, "bytes_per_sec"] = df.loc[bad, "byte_count"] / df.loc[bad, "flow_duration"]
    else:
        df["bytes_per_sec"] = df["byte_count"] / df["flow_duration"]

    return df


def _compute_source_profiles(df: pd.DataFrame) -> pd.DataFrame:
    """Derive per-source unique_dst_ports, unique_dst_ips, port_entropy.

    When CICIDS2017 includes IP/port columns, we group each source IP across
    all its flows in the dataset to approximate the same per-source statistics
    that NetSentinel computes within a live 10-second window.  When IP columns
    are absent every flow gets neutral defaults (single destination).
    """
    has_ip = "_src_ip" in df.columns and "_dst_ip" in df.columns and "_dst_port" in df.columns

    if not has_ip:
        print("  [INFO] IP/port columns absent — using per-flow defaults for source profile features.")
        df["unique_dst_ports"] = 1
        df["unique_dst_ips"] = 1
        df["port_entropy"] = 0.0
        return df

    def _entropy(ports: pd.Series) -> float:
        total = len(ports)
        if total == 0:
            return 0.0
        counts = Counter(ports)
        return float(-sum((c / total) * math.log2(c / total) for c in counts.values()))

    groups = df.groupby("_src_ip")
    unique_ports = groups["_dst_port"].nunique().rename("unique_dst_ports")
    unique_ips = groups["_dst_ip"].nunique().rename("unique_dst_ips")
    entropies = groups["_dst_port"].apply(_entropy).rename("port_entropy")

    profile = pd.concat([unique_ports, unique_ips, entropies], axis=1)
    df = df.merge(profile, left_on="_src_ip", right_index=True, how="left", suffixes=("", "_agg"))
    # Fill any unmatched rows (shouldn't happen but be safe)
    df["unique_dst_ports"] = df.get("unique_dst_ports", pd.Series(1, index=df.index)).fillna(1).astype(int)
    df["unique_dst_ips"] = df.get("unique_dst_ips", pd.Series(1, index=df.index)).fillna(1).astype(int)
    df["port_entropy"] = df.get("port_entropy", pd.Series(0.0, index=df.index)).fillna(0.0)
    return df


def _clean(df: pd.DataFrame) -> pd.DataFrame:
    before = len(df)
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=FEATURE_COLUMNS)
    after = len(df)
    if after < before:
        print(f"  [INFO] Dropped {before - after:,} rows containing NaN/Inf values.")
    return df


# ---------------------------------------------------------------------------
# Label handling
# ---------------------------------------------------------------------------

def _extract_labels(df: pd.DataFrame) -> pd.Series | None:
    if "_label" not in df.columns:
        return None
    labels = df["_label"].str.strip()
    return (labels != _BENIGN_LABEL).astype(int)  # 0 = benign, 1 = attack


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def _evaluate(model: IsolationForest, X: np.ndarray, y_true: pd.Series) -> None:
    raw = model.predict(X)          # 1 = normal, -1 = anomaly
    y_pred = (raw == -1).astype(int)  # 1 = predicted anomaly

    print("\n--- Evaluation ---")
    print(f"  Samples  : {len(y_true):,}  (benign={int((y_true == 0).sum()):,}  attack={int((y_true == 1).sum()):,})")

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
    print(f"  TP={tp:,}  FP={fp:,}  TN={tn:,}  FN={fn:,}")
    print()
    print(classification_report(y_true, y_pred, target_names=["benign", "attack"], zero_division=0))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train a NetSentinel Isolation Forest on the CICIDS2017 dataset.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "dataset",
        nargs="+",
        help="Path(s) to CICIDS2017 CSV file(s) or a directory containing them.",
    )
    parser.add_argument(
        "--output",
        default="models/isolation_forest.joblib",
        help="Output model path (default: models/isolation_forest.joblib).",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=None,
        help=(
            "Expected fraction of anomalies seen during training.  "
            "Defaults to the actual attack ratio in the dataset when labels are present, "
            "otherwise 0.08."
        ),
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=300,
        help="Number of trees in the Isolation Forest (default: 300).",
    )
    parser.add_argument(
        "--no-eval",
        action="store_true",
        help="Skip evaluation (faster; no label column required).",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=None,
        help="Subsample the dataset to at most N rows (useful for quick iteration).",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # ---- Load ---------------------------------------------------------------
    print("Loading dataset(s) …")
    paths = _resolve_paths(args.dataset)
    df = _load_csvs(paths)
    print(f"  {len(df):,} rows loaded from {len(paths)} file(s).")

    if args.max_rows and len(df) > args.max_rows:
        df = df.sample(n=args.max_rows, random_state=42)
        print(f"  Subsampled to {args.max_rows:,} rows.")

    # ---- Preprocess ---------------------------------------------------------
    print("Preprocessing …")
    df = _map_columns(df)
    df = _derive_features(df)
    df = _compute_source_profiles(df)
    df = _clean(df)

    y = _extract_labels(df)

    if y is not None:
        attack_ratio = float(y.mean())
        benign_n = int((y == 0).sum())
        attack_n = int((y == 1).sum())
        print(f"  Labels: {benign_n:,} benign / {attack_n:,} attack  ({attack_ratio:.1%} attack rate)")
    else:
        attack_ratio = None
        print("  No Label column found — training on all rows.")

    # ---- Feature matrix for BENIGN-only training ----------------------------
    if y is not None:
        X_train = df.loc[y == 0, FEATURE_COLUMNS].to_numpy(dtype=np.float64)
        print(f"  Training set: {len(X_train):,} BENIGN rows × {len(FEATURE_COLUMNS)} features.")
    else:
        X_train = df[FEATURE_COLUMNS].to_numpy(dtype=np.float64)
        print(f"  Training set: {len(X_train):,} rows × {len(FEATURE_COLUMNS)} features.")

    X_full = df[FEATURE_COLUMNS].to_numpy(dtype=np.float64)

    # ---- Contamination ------------------------------------------------------
    if args.contamination is not None:
        contamination = args.contamination
    elif attack_ratio is not None and attack_ratio > 0:
        # Use the actual proportion of attacks as the contamination hint.
        # IsolationForest expects this relative to the *full* dataset, but we
        # train on BENIGN-only, so set it low to prefer high recall on attacks.
        contamination = min(max(attack_ratio, 0.01), 0.5)
    else:
        contamination = 0.08
    print(f"  Contamination: {contamination:.4f}")

    # ---- Train --------------------------------------------------------------
    print(f"Training IsolationForest (n_estimators={args.n_estimators}) …")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        model = IsolationForest(
            contamination=contamination,
            n_estimators=args.n_estimators,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X_train)
    print("  Training complete.")

    # ---- Evaluate -----------------------------------------------------------
    if not args.no_eval and y is not None:
        _evaluate(model, X_full, y)
    elif not args.no_eval and y is None:
        print("  Skipping evaluation: no Label column in dataset.")

    # ---- Save ---------------------------------------------------------------
    version = stable_sha256(
        {
            "datasets": [str(p) for p in paths],
            "feature_columns": FEATURE_COLUMNS,
            "n_train": int(len(X_train)),
            "contamination": contamination,
            "n_estimators": args.n_estimators,
        }
    )[:12]

    metadata = {
        "version": version,
        "feature_columns": FEATURE_COLUMNS,
        "contamination": contamination,
        "n_estimators": args.n_estimators,
        "n_train_samples": int(len(X_train)),
        "datasets": [str(p) for p in paths],
    }

    joblib.dump({"model": model, "version": version, "metadata": metadata}, output_path)
    print(f"\nModel saved → {output_path}  (version={version})")


if __name__ == "__main__":
    main()
