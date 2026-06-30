"""Train XGBoost malware classifier on labeled samples."""

import argparse
import json
from pathlib import Path

import numpy as np

from app.services.ml.scorer import FEATURE_NAMES, extract_features
from app.services.sandbox.executor import run_sandbox
from app.services.static.analyzer import analyze_static


def load_labeled_samples(samples_dir: Path) -> tuple[np.ndarray, np.ndarray]:
    features_list = []
    labels = []

    for sample_path in samples_dir.glob("*"):
        if not sample_path.is_file():
            continue
        data = sample_path.read_bytes()
        label = 1 if "malware" in sample_path.name.lower() or "bad" in sample_path.name.lower() else 0

        static = analyze_static(data, sample_path.name)
        sandbox = run_sandbox(data, static)
        feats = extract_features(static, sandbox)
        features_list.append([feats[name] for name in FEATURE_NAMES])
        labels.append(label)

    if not features_list:
        raise ValueError(f"No samples found in {samples_dir}")

    return np.array(features_list), np.array(labels)


def main():
    parser = argparse.ArgumentParser(description="Train ThreatVault ML classifier")
    parser.add_argument("--samples", type=Path, default=Path("./samples"))
    parser.add_argument("--output", type=Path, default=Path("./models/malware_classifier.json"))
    args = parser.parse_args()

    X, y = load_labeled_samples(args.samples)

    try:
        import xgboost as xgb

        dtrain = xgb.DMatrix(X, label=y, feature_names=FEATURE_NAMES)
        params = {
            "objective": "binary:logistic",
            "max_depth": 6,
            "eta": 0.1,
            "eval_metric": "auc",
        }
        model = xgb.train(params, dtrain, num_boost_round=50)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        model.save_model(str(args.output))
        print(f"XGBoost model saved to {args.output}")
    except ImportError:
        from sklearn.ensemble import GradientBoostingClassifier
        import joblib

        clf = GradientBoostingClassifier(n_estimators=100, max_depth=4)
        clf.fit(X, y)
        args.output = args.output.with_suffix(".pkl")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(clf, args.output)
        print(f"sklearn model saved to {args.output}")


if __name__ == "__main__":
    main()
# Project version: ThreatVault V1.2
