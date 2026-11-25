#!/usr/bin/env python3
"""
Maria IDS - LightGBM Model Trainer

Trains a compact, high-speed LightGBM model from network intrusion datasets
(such as UNSW-NB15, CIC-IDS2017, or custom PCAP CSVs) and exports it for real-time
evaluation in Maria IDS.
"""

import argparse
import os
import sys

def main():
    parser = argparse.ArgumentParser(description="Train a compact LightGBM model for Maria IDS")
    parser.add_argument("--data", type=str, required=True, help="Path to CSV dataset (e.g., UNSW_NB15_training-set.csv)")
    parser.add_argument("--output", type=str, default="userspace/models/maria_lgbm_model.txt", help="Output model path")
    parser.add_argument("--trees", type=int, default=50, help="Number of boosting trees (default: 50 for <150KB size)")
    parser.add_argument("--max-depth", type=int, default=6, help="Maximum tree depth for microsecond latency (default: 6)")
    args = parser.parse_args()

    try:
        import lightgbm as lgb
        import pandas as pd
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report, roc_auc_score
    except ImportError:
        print("[!] Required ML libraries not found. Install them with:")
        print("    pip install lightgbm pandas scikit-learn")
        sys.exit(1)

    print(f"[*] Loading dataset from {args.data}...")
    df = pd.read_csv(args.data)
    print(f"[*] Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")

    # Map dataset columns to Maria IDS feature vector
    # Auto-detect label column
    label_col = None
    for candidate in ["label", "Label", "attack", "is_attack", "class"]:
        if candidate in df.columns:
            label_col = candidate
            break

    if not label_col:
        print(f"[!] Could not auto-detect label column. Available columns: {list(df.columns)}")
        sys.exit(1)

    y = df[label_col]
    if y.dtype == object:
        # Binary mapping: 'Normal' / 'BENIGN' = 0, others = 1
        y = (~y.str.upper().isin(["NORMAL", "BENIGN"])).astype(int)

    # Feature selection matching Maria IDS real-time extraction:
    # [dst_port_risk, src_ephemeral, proto_num, tcp_flags, total_len, payload_len, entropy, unique_ports_rate, syn_rate]
    candidate_features = []
    for col in ["sport", "dsport", "proto", "sbytes", "dbytes", "sttl", "rate", "sload", "dur"]:
        if col in df.columns:
            candidate_features.append(col)

    if not candidate_features:
        # Fallback to all numerical columns except label
        candidate_features = [c for c in df.select_dtypes(include=["number"]).columns if c != label_col]

    print(f"[*] Training on features: {candidate_features}")
    X = df[candidate_features].fillna(0)

    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

    train_data = lgb.Dataset(X_train, label=y_train)
    val_data = lgb.Dataset(X_val, label=y_val, reference=train_data)

    params = {
        "objective": "binary",
        "metric": "auc",
        "boosting_type": "gbdt",
        "num_leaves": 31,
        "max_depth": args.max_depth,
        "learning_rate": 0.05,
        "verbose": -1,
    }

    print(f"[*] Training LightGBM model ({args.trees} trees, max_depth={args.max_depth})...")
    model = lgb.train(
        params,
        train_data,
        num_boost_round=args.trees,
        valid_sets=[val_data],
    )

    y_pred = model.predict(X_val)
    auc = roc_auc_score(y_val, y_pred)
    print(f"\n[+] Training complete! Validation ROC-AUC: {auc:.4f}")

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    model.save_model(args.output)
    size_kb = os.path.getsize(args.output) / 1024
    print(f"[+] Model saved to: {args.output} ({size_kb:.1f} KB)")
    print("[*] To use this model in Maria IDS, start the daemon with:")
    print(f"    python3 userspace/daemon.py --ml-model {args.output}")

if __name__ == "__main__":
    main()
