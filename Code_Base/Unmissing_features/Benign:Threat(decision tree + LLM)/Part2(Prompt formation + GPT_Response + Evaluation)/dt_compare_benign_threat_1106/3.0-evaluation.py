import json
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Load JSON data
with open('dt_compare_benign_threat/output/final_data_without_prob.json', 'r') as file:
    data = json.load(file)

# Assuming the JSON object is a list of dictionaries where each dictionary has 'prediction' and 'actual' keys
predictions = [item[3] for item in data]
actual_labels = [item[1] for item in data]

# Calculate the metrics
accuracy = accuracy_score(actual_labels, predictions)
precision = precision_score(actual_labels, predictions, average='macro')  # Adjusted for multi-class
recall = recall_score(actual_labels, predictions, average='macro')  # Adjusted for multi-class
f1 = f1_score(actual_labels, predictions, average='macro')  # Adjusted for multi-class

print(f"Sampel size: {len(data):}")
print(f"Accuracy: {accuracy:.2f}")
print(f"Precision: {precision:.2f}")
print(f"Recall: {recall:.2f}")
print(f"F1 Score: {f1:.2f}")

# File to write the mismatches
output_file = 'dt_compare_benign_threat/output/mismatched_predictions.txt'

# Open the file in write mode
with open(output_file, 'w') as file:
    # Write a header or any initial descriptions if necessary
    file.write("List of mismatched predictions and actual labels:\n")
    
    # Iterate over the predictions and actual labels to find mismatches
    for i, (prediction, actual_label) in enumerate(zip(predictions, actual_labels)):
        if prediction != actual_label:
            # Write the mismatch information to the file
            file.write(f"Row {i}: Prediction = {prediction}, Actual Label = {actual_label}\n")

print("Mismatched predictions have been written to:", output_file)
