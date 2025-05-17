import pandas as pd
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Constants
MODEL_FILE = "url_model.pkl"
DATASET_PATH = "urldataset.csv"  # Dataset is in the same folder as this script

def train_model(dataset_path=DATASET_PATH):
    print("🔧 Training model...")
    
    # Load dataset
    df = pd.read_csv(dataset_path, sep="\t")
    
    # Split into features and labels
    X = df.drop(columns=["domain", "label"])  # Drop non-feature columns
    y = df["label"]

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # Model training
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    # Save model
    joblib.dump(clf, MODEL_FILE)

    # Evaluation
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print("✅ Model trained and saved as url_model.pkl")
    print(f"📈 Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred))


def load_model():
    """Load model from file, train if not found."""
    if not os.path.exists(MODEL_FILE):
        train_model()
    return joblib.load(MODEL_FILE)


def predict_url(features: dict):
    """
    Predict whether a URL is safe or phishing based on extracted features.

    Args:
        features (dict): Dictionary of features as expected by the model.

    Returns:
        dict: {
            'prediction': 0 or 1,
            'confidence': float (in percentage)
        }
    """
    model = load_model()
    input_df = pd.DataFrame([features])
    prediction = model.predict(input_df)[0]
    probability = model.predict_proba(input_df)[0].max()
    return {
        "prediction": int(prediction),
        "confidence": round(probability * 100, 2)
    }


# Optional direct training run
if __name__ == "__main__":
    train_model()
