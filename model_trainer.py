# model_trainer.py
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

def train_model(X_train, X_test, y_train, y_test):
    """
    Train a RandomForest model and return both the model and accuracy.
    """
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )
    model.fit(X_train, y_train)

    # predictions on test data
    y_pred = model.predict(X_test)

    # calculate accuracy
    accuracy = accuracy_score(y_test, y_pred)

    return model, accuracy

