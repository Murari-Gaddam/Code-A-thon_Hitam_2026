import pandas as pd
from detector import IntrusionDetector

DATASET = "test_sample.csv"

print("Loading test dataset...")
df = pd.read_csv(DATASET)

print(f"Loaded {len(df)} rows")

# Keep the ground-truth label separately
true_labels = df["Label"].copy()

# Remove label before sending to detector
X = df.drop(columns=["Label"])

# Initialize detector
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

# Convert results to DataFrame
results_df = pd.DataFrame(results)

# Add ground truth
results_df["true_label"] = true_labels.values

# Save
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