import json

# Load the first JSON data
with open('dt_compare/input/integrated_data.json', 'r') as file:
    data = json.load(file)

# Define default value for gpt_reason
default_gpt_reason = "Data unavailable for prediction."

# Update second_data based on the first_data map using 'Row' key
for item in data:
    row = item['Row']

    predictions = [(item.get('Prediction_1'), item.get('Accuracy_1')),
                    (item.get('Prediction_2'), item.get('Accuracy_2'))]
    # Filter out None values and sort by accuracy
    predictions = [pred for pred in predictions if pred[0] is not None and pred[1] is not None]
    if predictions:
        item['highest'] = max(predictions, key=lambda x: x[1])[0]
    else:
        item['highest'] = 'Unknown'  # Default when no predictions are available
        print("error")
    item['gpt_reason'] = default_gpt_reason

with open('dt_compare/input/highest_accuracy.json', 'w') as file:
    json.dump(data, file, indent=4)

print("The second JSON file has been updated and saved.")
