from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
from dataset_generator import generate_dataset
from model_trainer import train_model

def retrain_model():
    X, y = generate_dataset()
    
    # Split dataset into train/test
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train
    model = train_model(X_train, y_train)

    # Predict
    y_pred_train = model.predict(X_train)
    y_pred_test = model.predict(X_test)

    # Accuracy
    train_acc = accuracy_score(y_train, y_pred_train)
    test_acc = accuracy_score(y_test, y_pred_test)

    # Save model
    joblib.dump(model, "ransomware_model.pkl")

    return train_acc, test_acc
