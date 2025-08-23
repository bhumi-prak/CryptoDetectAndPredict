# dataset_generator.py
import numpy as np
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split

def generate_dataset(n_samples=1000, n_features=20, n_classes=2, test_size=0.2):
    """
    Generate synthetic dataset for ransomware detection and split into train/test.
    """
    X, y = make_classification(
        n_samples=n_samples,
        n_features=n_features,
        n_informative=10,
        n_redundant=5,
        n_classes=n_classes,
        random_state=42
    )

    # split into train/test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42
    )

    return X_train, X_test, y_train, y_test
