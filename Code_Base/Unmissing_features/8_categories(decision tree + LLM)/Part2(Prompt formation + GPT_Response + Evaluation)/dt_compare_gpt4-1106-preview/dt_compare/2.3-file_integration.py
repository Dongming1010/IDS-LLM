import json
import string

# Function to parse the GPT response
def parse_response(response):
    """Parse the response to extract the traffic type and include all subsequent content, excluding only the first line."""
    # Define the list of valid traffic types
    valid_traffic_types = ['Benign Traffic', 'Recon\nThe most plausible path is from the second tree','BenignTraffic', 'DDoS', 'Brute_Force', 'Spoofing', 'DoS', 'Recon', 'Web-Based', 'Mirai']

    # Split the response into sections based on double newlines
    parts = response.split('\n\n')
    
    # Extract the type of traffic from the first part, removing any trailing punctuation and whitespace
    traffic_type_line = parts[0]
    traffic_type = traffic_type_line.split(': ')[1].strip().rstrip(string.punctuation).strip()
    
    # Combine all content after the first line, which is the traffic type
    chosen_path_and_rationale = '\n\n'.join(parts[1:])  # Use everything except the first part

    if traffic_type == 'Benign Traffic':
        traffic_type = 'BenignTraffic'
    if traffic_type == 'Recon\nThe most plausible path is from the second tree':
        traffic_type = 'Recon'
    # Check if the traffic type is valid
    if traffic_type not in valid_traffic_types:
        # Print a message indicating the invalid traffic type
        print(f"Invalid traffic type encountered: '{traffic_type}'.")
        return None  # Optionally return None or handle as needed

    return {
        'traffic_type': traffic_type,
        'chosen_path_and_rationale': chosen_path_and_rationale
    }

# Load the initial data
with open('dt_compare/matching_predictions.json', 'r') as file:
    original_data = json.load(file)

# Load the responses from GPT
# with open('dt_compare/withou_background_info/analysis_input_with_prob_results.jsonl', 'r') as file:
with open('dt_compare/analysis_input_without_prob_results.jsonl', 'r') as file:
    responses = [json.loads(line) for line in file.readlines()]

# Check that the number of responses matches the number of entries
assert len(responses) == len(original_data), "Mismatch in number of entries and responses"

correct_predictions = 0

# Process each response and update the original data
for entry, response in zip(original_data, responses):
    parsed_response = parse_response(response)
    gpt_choice = parsed_response['traffic_type']
    reason = parsed_response['chosen_path_and_rationale']

    if gpt_choice == entry['Label']:
        correct_predictions += 1
        
    # Update the entry
    entry['gpt_choice'] = gpt_choice
    entry['gpt_reason'] = reason

# Save the updated data to a new file
# with open('dt_compare/withou_background_info/updated_matching_predictions_with_prob.json', 'w') as file:
with open('dt_compare/updated_matching_predictions_without_prob.json', 'w') as file:
    json.dump(original_data, file, indent=4)
    
accuracy = correct_predictions / len(original_data)
print("Number of correct choice: " + str(correct_predictions) + " out of " + str(len(original_data)))
print("Accuracy: " + str(accuracy))

print("Updated data with GPT responses saved successfully.")