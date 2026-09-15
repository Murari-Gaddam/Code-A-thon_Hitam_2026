import joblib
import numpy as np
import pandas as pd
from scipy.special import softmax


class TemperatureScaledClassifier:
    def __init__(self, base_estimator=None, T_=1.0):
        self.base_estimator = base_estimator
        self.T_ = T_

    def predict_proba(self, X):
        base_proba = self.base_estimator.predict_proba(X)

        # Numerical stability
        base_proba = np.clip(base_proba, 1e-12, 1.0)

        # Convert probabilities to logits
        logits = np.log(base_proba)

        # Temperature scaling
        scaled_logits = logits / self.T_

        return softmax(scaled_logits, axis=1)

    def predict(self, X):
        proba = self.predict_proba(X)
        return np.argmax(proba, axis=1)


import __main__
__main__.TemperatureScaledClassifier = TemperatureScaledClassifier

import os

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "cicids2017-soc-classifier-v2",
    "model"
)


class IntrusionDetector:

    def __init__(self):

        print("Loading IDS model...")

        self.label_encoder = joblib.load(
            f"{MODEL_DIR}/label_encoder.pkl"
        )

        self.scaler = joblib.load(
            f"{MODEL_DIR}/scaler.pkl"
        )

        self.selector = joblib.load(
            f"{MODEL_DIR}/feature_selector.pkl"
        )

        self.isolation_forest = joblib.load(
            f"{MODEL_DIR}/stage1_isolation_forest.pkl"
        )

        self.classifier = joblib.load(
            f"{MODEL_DIR}/tier1_lgbm_temp_scaled.pkl"
        )

        self.thresholds = joblib.load(
            f"{MODEL_DIR}/pipeline_thresholds.pkl"
        )

        self.feature_cols = joblib.load(
            f"{MODEL_DIR}/feature_cols.pkl"
        )

        self.selected_features = joblib.load(
            f"{MODEL_DIR}/selected_features.pkl"
        )

        print("Model loaded successfully!")

        print("\nClasses:")
        print(self.label_encoder.classes_)

        print("\nThresholds:")
        print(self.thresholds)

        print("\nExpected features:")
        print(len(self.feature_cols))


    def predict(self, flow):

        if isinstance(flow, dict):

            flow = pd.DataFrame([flow])

        elif isinstance(flow, pd.Series):

            flow = flow.to_frame().T


        missing = [
            col
            for col in self.feature_cols
            if col not in flow.columns
        ]

        if missing:

            raise ValueError(
                f"Missing {len(missing)} features: "
                f"{missing}"
            )


        X = flow[self.feature_cols]

        X = X.values.astype("float32")


        X = self.scaler.transform(X)

        X = self.selector.transform(X)


        iso_pred = self.isolation_forest.predict(X)


        # Anomaly / OOD
        if iso_pred[0] == -1:

            return {
                "status": "SUSPICIOUS",
                "attack_type": "Unknown",
                "confidence": None,
                "anomaly": True,
                "stage_1": "anomaly"
            }


        proba = self.classifier.predict_proba(X)

        class_index = np.argmax(proba[0])

        prediction = self.label_encoder.classes_[
            class_index
        ]

        confidence = float(
            proba[0][class_index]
        )


        conf_threshold = self.thresholds.get(
            "CONF_THRESHOLD",
            0.60
        )

        if confidence < conf_threshold:

            return {
                "status": "SUSPICIOUS",
                "attack_type": "Unknown",
                "confidence": confidence,
                "anomaly": False,
                "stage_1": "inlier"
            }


        if prediction == "Normal":

            status = "NORMAL"

        else:

            status = "ATTACK"


        return {
            "status": status,
            "attack_type": prediction,
            "confidence": confidence,
            "anomaly": False,
            "stage_1": "inlier"
        }