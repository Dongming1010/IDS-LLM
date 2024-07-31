import json
import string
import pandas as pd
idx = 0
# Function to parse the GPT response
def parse_response(response):
    """Parse the response to extract the traffic type and include all subsequent content, excluding only the first line."""
    # Define the list of valid traffic types
    valid_traffic_types = ['BenignTraffic', 'Benign Traffic', 'Brute Force', 'Web Based', 'DDoS', 'Brute_Force', 
                           'DoS (Denial of Service', 'DDoS (Distributed Denial of Service', 'Spoofing', 'DoS', 'Recon', 'Web-Based', 'Mirai']

    # Split the response into sections based on double newlines
    parts = response.split('\n\n')
    
    # Extract the type of traffic from the first part, removing any trailing punctuation and whitespace
    traffic_type_line = parts[0]
    traffic_type = traffic_type_line.split(': ')[1].strip().rstrip(string.punctuation).strip()
    
    # Combine all content after the first line, which is the traffic type
    chosen_path_and_rationale = '\n\n'.join(parts[1:])  # Use everything except the first part

    if traffic_type == 'Benign Traffic':
        traffic_type = 'BenignTraffic'
    if traffic_type == 'Web Based':
        traffic_type = 'Web-Based'
    if traffic_type == 'Brute Force':
        traffic_type = 'Brute_Force'
    if traffic_type == 'DoS (Denial of Service':
        traffic_type = 'DoS'
    if traffic_type == 'DDoS (Distributed Denial of Service':
        traffic_type = 'DDoS'
    # Check if the traffic type is valid
    global idx
    idx += 1
    if traffic_type not in valid_traffic_types:
        print(idx)
        # Print a message indicating the invalid traffic type
        print(f"Invalid traffic type encountered: '{traffic_type}'.")
        return None  # Optionally return None or handle as needed

    return {
        'traffic_type': traffic_type,
        'chosen_path_and_rationale': chosen_path_and_rationale
    }

# Load the initial data from CSV
original_data = pd.read_csv('source/renamed_5000_data.csv')

# Load the responses from GPT
with open('output/network_traffic_classification_results.jsonl', 'r') as file:
    responses = [json.loads(line) for line in file.readlines()]

# Check that the number of responses matches the number of entries
assert len(responses) == len(original_data), "Mismatch in number of entries and responses"

correct_predictions = 0

# Process each response and update the original data
for index, response in enumerate(responses):
    parsed_response = parse_response(response)  # Assuming response is the key where the actual text response is stored
    if parsed_response:
        gpt_choice = parsed_response['traffic_type']
        reason = parsed_response['chosen_path_and_rationale']
        
        if gpt_choice == original_data.loc[index, 'label']:
            correct_predictions += 1
        
        # Update the entry
        original_data.loc[index, 'prediction'] = gpt_choice
        original_data.loc[index, 'reason'] = reason

# Save the updated data to a new CSV file
original_data.to_csv('source/prediction_5000_data.csv', index=False)
    
accuracy = correct_predictions / len(original_data)
print("Number of correct choices: " + str(correct_predictions) + " out of " + str(len(original_data)))
print("Accuracy: " + str(accuracy))

print("Updated data with GPT responses saved successfully.")
