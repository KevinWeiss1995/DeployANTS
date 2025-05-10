import pandas as pd
import numpy as np
import os
from utils.git import get_git_repo_root
from sklearn.model_selection import train_test_split

def load_data():
    """
    Loads and preprocesses the network traffic data.
    
    Returns:
        X, y: Training data and labels
        X_val, y_val: Validation data and labels
        feature_names: List of feature names
    """
    base_repo = get_git_repo_root()
    data_dir = os.path.join(base_repo, 'data', 'network')
  
    train_data = pd.read_csv(os.path.join(data_dir, 'train_data.csv'))
    train_labels = pd.read_csv(os.path.join(data_dir, 'train_labels.csv'))
    test_data = pd.read_csv(os.path.join(data_dir, 'test_data.csv'))
    test_labels = pd.read_csv(os.path.join(data_dir, 'test_labels.csv'))

    X_train, X_val, y_train, y_val = train_test_split(train_data, train_labels, test_size=0.2, random_state=42)

    X = X_train.values
    y = y_train.values.ravel()
    X_val = X_val.values
    y_val = y_val.values.ravel()

    feature_names = train_data.columns.tolist()
    feature_file_path = os.path.join(base_repo, 'results', 'models', 'network', 'network_features.txt')
    os.makedirs(os.path.dirname(feature_file_path), exist_ok=True)
    
    with open(feature_file_path, 'w') as f:
        for feature in feature_names:
            f.write(f"{feature}\n")
            
    return X, y, X_val, y_val, feature_names
