#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Cyber Guardian - Complete Model Training Script
Trains all security models for the Cyber Guardian application
"""

import os
import sys
import pandas as pd
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder
from datetime import datetime

print("=" * 70)
print("🛡️  Cyber Guardian - Complete Model Training Suite")
print("=" * 70)
print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 70)


# ======================== HELPER FUNCTIONS ========================

def prepare_features(df, feature_cols, label_col):
    """Prepare features and labels for training"""
    df_copy = df.copy()
    
    for col in feature_cols:
        if col in df_copy.columns:
            if df_copy[col].dtype == 'object':
                df_copy[col] = pd.Categorical(df_copy[col]).codes
            elif df_copy[col].dtype == 'bool':
                df_copy[col] = df_copy[col].astype(int)
    
    if label_col in df_copy.columns:
        if df_copy[label_col].dtype == 'object':
            df_copy[label_col] = pd.Categorical(df_copy[label_col]).codes
        elif df_copy[label_col].dtype == 'bool':
            df_copy[label_col] = df_copy[label_col].astype(int)
    
    existing_features = [col for col in feature_cols if col in df_copy.columns]
    X = df_copy[existing_features] if existing_features else pd.DataFrame()
    y = df_copy[label_col] if label_col in df_copy.columns else pd.Series()
    
    return X, y


# ======================== TRAINING FUNCTIONS ========================

def train_phishing_model():
    """Train phishing detection model"""
    print("\n" + "=" * 60)
    print("📚 1. TRAINING PHISHING DETECTION MODEL")
    print("=" * 60)
    
    try:
        df = pd.read_csv('dataset/phishing_dataset.csv')
        print(f"✅ Loaded {len(df)} records from phishing_dataset.csv")
        print(f"   Columns: {list(df.columns)}")
        
        feature_cols = ['url_len', 'host_len', 'fd_len', 'dot_count', 'hyphen_count', 
                       'underscore_count', 'percent_count', 'query_count', 'slash_count', 
                       'digit_count', 'letter_count', 'dir_count', 'has_ip']
        label_col = 'label'
        
        X, y = prepare_features(df, feature_cols, label_col)
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
        model.fit(X_train, y_train)
        
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred) * 100
        
        print(f"📊 Accuracy: {accuracy:.2f}%")
        print("\n📋 Classification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        joblib.dump(model, 'phishing_model.pkl')
        print("💾 Model saved as 'phishing_model.pkl' ✅")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def train_port_scanner_model():
    """Train port scanner model"""
    print("\n" + "=" * 60)
    print("📚 2. TRAINING PORT SCANNER MODEL")
    print("=" * 60)
    
    try:
        df = pd.read_csv('dataset/ports_dataset.csv')
        print(f"✅ Loaded {len(df)} port records from ports_dataset.csv")
        print(f"   Columns: {list(df.columns)}")
        
        feature_cols = ['port', 'cve_count']
        for col in df.columns:
            if df[col].dtype in ['int64', 'float64'] and col != 'port':
                if col not in feature_cols:
                    feature_cols.append(col)
        
        label_col = None
        for col in ['is_vulnerable', 'vulnerable', 'risk_level']:
            if col in df.columns:
                label_col = col
                break
        if label_col is None:
            label_col = df.columns[-1]
        
        X, y = prepare_features(df, feature_cols, label_col)
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred) * 100
        
        print(f"📊 Accuracy: {accuracy:.2f}%")
        
        joblib.dump(model, 'port_scanner_model.pkl')
        print("💾 Model saved as 'port_scanner_model.pkl' ✅")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def train_firewall_model():
    """Train firewall model"""
    print("\n" + "=" * 60)
    print("📚 3. TRAINING FIREWALL SECURITY MODEL")
    print("=" * 60)
    
    try:
        df = pd.read_csv('dataset/firewall_dataset.csv')
        print(f"✅ Loaded {len(df)} firewall records from firewall_dataset.csv")
        print(f"   Columns: {list(df.columns)}")
        
        feature_cols = []
        for col in df.columns:
            if df[col].dtype in ['int64', 'float64']:
                feature_cols.append(col)
        
        if not feature_cols:
            for col in df.columns:
                if col not in ['os_type', 'firewall_status']:
                    feature_cols.append(col)
        
        label_col = 'is_secure' if 'is_secure' in df.columns else df.columns[-1]
        
        X, y = prepare_features(df, feature_cols, label_col)
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred) * 100
        
        print(f"📊 Accuracy: {accuracy:.2f}%")
        
        joblib.dump(model, 'firewall_model.pkl')
        print("💾 Model saved as 'firewall_model.pkl' ✅")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def train_patch_model():
    """Train patch model"""
    print("\n" + "=" * 60)
    print("📚 4. TRAINING PATCH MANAGEMENT MODEL")
    print("=" * 60)
    
    try:
        df = pd.read_csv('dataset/patch_dataset.csv')
        print(f"✅ Loaded {len(df)} patch records from patch_dataset.csv")
        print(f"   Columns: {list(df.columns)}")
        
        feature_cols = []
        for col in df.columns:
            if df[col].dtype in ['int64', 'float64']:
                feature_cols.append(col)
        
        if not feature_cols and 'days_outdated' in df.columns:
            feature_cols = ['days_outdated']
        
        label_col = None
        for col in ['needs_update', 'requires_reboot', 'severity']:
            if col in df.columns:
                label_col = col
                break
        if label_col is None:
            label_col = df.columns[-1]
        
        X, y = prepare_features(df, feature_cols, label_col)
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred) * 100
        
        print(f"📊 Accuracy: {accuracy:.2f}%")
        
        joblib.dump(model, 'patch_model.pkl')
        print("💾 Model saved as 'patch_model.pkl' ✅")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def train_process_model():
    """Train process model"""
    print("\n" + "=" * 60)
    print("📚 5. TRAINING PROCESS DETECTION MODEL")
    print("=" * 60)
    
    try:
        df = pd.read_csv('dataset/process_dataset.csv')
        print(f"✅ Loaded {len(df)} process records from process_dataset.csv")
        print(f"   Columns: {list(df.columns)}")
        
        feature_cols = []
        for col in df.columns:
            if df[col].dtype in ['int64', 'float64']:
                feature_cols.append(col)
        
        if not feature_cols:
            feature_cols = ['cpu_percent', 'memory_percent', 'num_threads', 'risk_score']
            feature_cols = [c for c in feature_cols if c in df.columns]
        
        label_col = None
        for col in ['suspicious', 'is_suspicious', 'risk_level']:
            if col in df.columns:
                label_col = col
                break
        if label_col is None:
            label_col = df.columns[-1]
        
        X, y = prepare_features(df, feature_cols, label_col)
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred) * 100
        
        print(f"📊 Accuracy: {accuracy:.2f}%")
        
        joblib.dump(model, 'process_model.pkl')
        print("💾 Model saved as 'process_model.pkl' ✅")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def train_users_model():
    """Train users model - Fixed with proper string to boolean conversion"""
    print("\n" + "=" * 60)
    print("📚 6. TRAINING USER ACCOUNT SECURITY MODEL")
    print("=" * 60)
    
    try:
        df = pd.read_csv('dataset/users_dataset.csv')
        print(f"✅ Loaded {len(df)} user records from users_dataset.csv")
        print(f"   Columns: {list(df.columns)}")
        
        # Feature columns
        feature_cols = ['password_age_days', 'is_active', 'is_admin', 'has_2fa']
        feature_cols = [c for c in feature_cols if c in df.columns]
        
        # Label column
        label_col = 'risk_level' if 'risk_level' in df.columns else df.columns[-1]
        
        print(f"   Using features: {feature_cols}")
        print(f"   Using label: '{label_col}'")
        
        # Prepare features
        X = df[feature_cols].copy()
        
        # Convert Yes/No to 1/0 for boolean columns
        for col in ['is_active', 'is_admin', 'has_2fa']:
            if col in X.columns:
                # Convert string 'Yes'/'No' to boolean then to int
                if X[col].dtype == 'object':
                    X[col] = X[col].map({'Yes': 1, 'No': 0, 'yes': 1, 'no': 0, True: 1, False: 0})
                elif X[col].dtype == 'bool':
                    X[col] = X[col].astype(int)
        
        # Convert password_age_days to numeric
        if 'password_age_days' in X.columns:
            X['password_age_days'] = pd.to_numeric(X['password_age_days'], errors='coerce')
        
        # Handle NaN in features
        if X.isnull().values.any():
            print("   ⚠️ NaN values detected in features. Filling with 0...")
            X = X.fillna(0)
        
        # Convert all to float
        X = X.astype(float)
        
        # Prepare labels - Convert risk_level to numeric
        if label_col in df.columns:
            y = df[label_col].copy()
            
            # Handle NaN in labels
            if y.isnull().values.any():
                print("   ⚠️ NaN values detected in labels. Removing those rows...")
                valid_mask = ~y.isnull()
                X = X[valid_mask]
                y = y[valid_mask]
            
            # Convert string labels to numeric using mapping
            if y.dtype == 'object':
                # Define mapping for risk levels
                risk_mapping = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
                
                # Also handle other possible values
                for val in y.unique():
                    if val not in risk_mapping and val is not None and not pd.isna(val):
                        if isinstance(val, str):
                            risk_mapping[val.upper()] = len(risk_mapping)
                        else:
                            risk_mapping[val] = len(risk_mapping)
                
                y = y.map(risk_mapping)
                
                # If any NaN after mapping, fill with 0
                if y.isnull().values.any():
                    y = y.fillna(0)
            
            # Convert to int
            y = y.astype(float).astype(int)
        else:
            y = df.iloc[:, -1].copy()
            if y.dtype == 'object':
                y = pd.Categorical(y).codes
            y = y.astype(float).astype(int)
        
        # Check if we have enough data
        if len(X) < 2:
            print("   ❌ Not enough data to train (need at least 2 samples)")
            return False
        
        print(f"   Training data shape: X={X.shape}, y={y.shape}")
        print(f"   Unique labels: {np.unique(y)}")
        
        # Split and train
        if len(X) >= 4 and len(np.unique(y)) > 1:
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            print(f"   Train size: {len(X_train)}, Test size: {len(X_test)}")
        else:
            X_train, y_train = X, y
            X_test, y_test = X, y
            print(f"   ⚠️ Small dataset: using all {len(X)} samples for training")
        
        # Create and train model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        
        # Evaluate
        if len(X_test) > 0 and len(np.unique(y_test)) > 1:
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred) * 100
            print(f"📊 Accuracy: {accuracy:.2f}%")
        else:
            print(f"📊 Model trained on {len(X_train)} samples (classification)")
        
        # Save model
        joblib.dump(model, 'users_model.pkl')
        print("💾 Model saved as 'users_model.pkl' ✅")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


# ======================== MAIN EXECUTION ========================

def main():
    """Train all models"""
    
    if not os.path.exists('dataset'):
        print("\n❌ ERROR: 'dataset' folder not found!")
        sys.exit(1)
    
    training_functions = [
        ('Phishing Model', train_phishing_model),
        ('Port Scanner Model', train_port_scanner_model),
        ('Firewall Model', train_firewall_model),
        ('Patch Model', train_patch_model),
        ('Process Model', train_process_model),
        ('Users Model', train_users_model)
    ]
    
    results = []
    
    for name, train_func in training_functions:
        print(f"\n🚀 Training {name}...")
        result = train_func()
        results.append((name, result))
    
    print("\n" + "=" * 70)
    print("📊 TRAINING SUMMARY")
    print("=" * 70)
    
    successful = [name for name, result in results if result]
    failed = [name for name, result in results if not result]
    
    print(f"\n✅ Successful: {len(successful)}/6 models")
    for name in successful:
        print(f"  ✅ {name}")
    
    if failed:
        print(f"\n❌ Failed: {len(failed)}/6 models")
        for name in failed:
            print(f"  ❌ {name}")
    
    print("\n" + "=" * 70)
    print(f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    model_files = [
        'phishing_model.pkl', 'port_scanner_model.pkl', 'firewall_model.pkl',
        'patch_model.pkl', 'process_model.pkl', 'users_model.pkl'
    ]
    
    print("\n📁 Generated Model Files:")
    for model_file in model_files:
        if os.path.exists(model_file):
            size = os.path.getsize(model_file) / 1024
            print(f"  ✅ {model_file} ({size:.1f} KB)")
        else:
            print(f"  ❌ {model_file} (MISSING)")
    
    print("\n" + "=" * 70)
    print("🎯 Done!")
    print("=" * 70)


if __name__ == "__main__":
    main()