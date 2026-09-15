import pandas as pd
from detector import IntrusionDetector

DATASET = "test_sample.csv"

print("Loading test dataset...")
df = pd.read_csv(DATASET)

print(f"Loaded {len(df)} rows")

true_labels = df["Label"].copy()

X = df.drop(columns=["Label"])

detector = IntrusionDetector()

print("\nRunning predictions...")

results = []

for i in range(len(X)):
    try:
        result = detector.predict(X.iloc[i])
        results.append(result)

    except Exception as e:
        print(f"Error on row {i}: {e}")
        results.append({
            "status": "ERROR",
            "attack_type": "Unknown",
            "confidence": None,
            "anomaly": False,
            "stage_1": "error"
        })

results_df = pd.DataFrame(results)

results_df["true_label"] = true_labels.values

results_df.to_csv("predictions.csv", index=False)

print("\n========================================")
print("PREDICTION COMPLETE")
print("========================================")

print("\nPredicted status:")
print(results_df["status"].value_counts())

print("\nPredicted attack types:")
print(results_df["attack_type"].value_counts())

print("\nGround truth:")
print(results_df["true_label"].value_counts())

print("\nFirst 10 predictions:")
print(
    results_df[
        ["status", "attack_type", "confidence", "anomaly", "true_label"]
    ].head(10).to_string(index=False)
)

print("\nSaved: predictions.csv")
