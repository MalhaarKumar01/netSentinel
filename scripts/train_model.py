from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from netsentinel.ml import FEATURE_COLUMNS
from netsentinel.security import stable_sha256


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train an Isolation Forest model for NetSentinel.")
    parser.add_argument("dataset", help="CSV dataset path.")
    parser.add_argument(
        "--output",
        default="models/isolation_forest.joblib",
        help="Output model path.",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.08,
        help="Expected anomaly ratio.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    dataset_path = Path(args.dataset)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    frame = pd.read_csv(dataset_path)
    missing = [column for column in FEATURE_COLUMNS if column not in frame.columns]
    if missing:
        raise ValueError(f"Dataset is missing required feature columns: {missing}")

    model = IsolationForest(
        contamination=args.contamination,
        n_estimators=300,
        random_state=42,
    )
    model.fit(frame[FEATURE_COLUMNS])
    version = stable_sha256({"dataset": str(dataset_path), "columns": FEATURE_COLUMNS})[:12]
    joblib.dump({"model": model, "version": version}, output_path)
    print(f"Saved model to {output_path} with version {version}")


if __name__ == "__main__":
    main()
