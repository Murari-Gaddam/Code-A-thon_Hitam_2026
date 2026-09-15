import pandas as pd
import random
from datetime import datetime, timedelta

df = pd.read_csv("predictions.csv")

random.seed(42)

# Generate simulated private network endpoints
source_ips = [
    f"192.168.1.{random.randint(10, 250)}"
    for _ in range(len(df))
]

destination_ips = [
    "192.168.1.1"
    for _ in range(len(df))
]

# Generate timestamps
start = datetime.now()

timestamps = [
    start + timedelta(seconds=i)
    for i in range(len(df))
]

# Confidence as percentage
confidence = (
    df["confidence"]
    .fillna(0)
    .mul(100)
    .round(2)
)

frontend = pd.DataFrame({
    "Timestamp": timestamps,
    "Source IP": source_ips,
    "Destination IP": destination_ips,
    "Status": df["status"],
    "Attack Type": df["attack_type"],
    "Confidence": confidence
})

frontend.to_csv("frontend_data.csv", index=False)

print("✅ frontend_data.csv created")
print("\nShape:", frontend.shape)
print("\nPreview:")
print(frontend.head(10).to_string(index=False))