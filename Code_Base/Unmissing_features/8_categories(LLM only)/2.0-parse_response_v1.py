import pandas as pd
import json
import re
idx = 0
def parse_prediction(response_text):
    # Define valid categories
    valid_categories = ['BenignTraffic', 'DDoS', 'Brute_Force', 'Spoofing', 'DoS', 'Recon', 'Web-Based', 'Mirai', 'Brute Force', 'Web Based']
    global idx
    idx += 1
    # Use regular expression to capture the specific traffic type after the colon
    prediction_match = re.search(r"Most likely type of traffic: ([\w\s-]+)", response_text)
    if prediction_match:
        prediction = prediction_match.group(1)
        # Check if the extracted prediction is in the list of valid categories
        if prediction in valid_categories:
            if prediction == "Brute Force":
                prediction = 'Brute_Force'
            if prediction == "Web Based":
                prediction = 'Web-Based'
            return prediction
        else:
            print(idx)
            print(prediction)
            return "Invalid category"  # Return this if the prediction is not in the list
    print(idx)
    return "Prediction not found"  # Return this if no match is found

def process_responses(file_path):
    predictions = []
    with open(file_path, 'r') as file:
        for line in file:
            prediction = parse_prediction(line.strip())  # Directly parse the line
            predictions.append(prediction)
    return predictions

# Path to your JSONL file containing the responses
response_file_path = 'output/network_traffic_classification_CoT_results.jsonl'
predictions = process_responses(response_file_path)

# Load the original CSV file
original_df = pd.read_csv('source/5000_data.csv')

# Add the predictions to the DataFrame
original_df['prediction'] = predictions

# Save the updated DataFrame to a new CSV file
original_df.to_csv('source/CoT_prediction_5000_data.csv', index=False)

print("Updated CSV file with predictions has been saved.")
