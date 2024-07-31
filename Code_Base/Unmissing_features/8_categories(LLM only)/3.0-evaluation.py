import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from collections import Counter

def calculate_metrics(data):
    # Ensure predictions and labels are all strings to avoid type mismatch issues
    data['prediction'] = data['prediction'].astype(str)
    data['label'] = data['label'].astype(str)
    
    # Calculate metrics
    accuracy = accuracy_score(data['label'], data['prediction'])
    precision = precision_score(data['label'], data['prediction'], average='weighted')
    recall = recall_score(data['label'], data['prediction'], average='weighted')
    f1 = f1_score(data['label'], data['prediction'], average='weighted')
    
    return accuracy, precision, recall, f1

# Load the updated CSV file which includes predictions
data = pd.read_csv('source/CoT_prediction_5000_data.csv')

# Calculate metrics
accuracy, precision, recall, f1 = calculate_metrics(data)
predictions = data['prediction'].tolist()
actual_labels = data['label'].tolist()
unique_predictions = set(predictions)
unique_actual_labels = set(actual_labels)

print("Unique Predictions:", unique_predictions)
print("Unique Actual Labels:", unique_actual_labels)
label_counts = Counter(actual_labels)
prediction_counts = Counter(predictions)

print("Actual Label Distribution:", label_counts)
print("Prediction Distribution:", prediction_counts)

# Print the results
print(f"Sample size: {len(data)}")
print(f"Accuracy: {accuracy:.2f}")
print(f"Precision: {precision:.2f}")
print(f"Recall: {recall:.2f}")
print(f"F1 Score: {f1:.2f}")
