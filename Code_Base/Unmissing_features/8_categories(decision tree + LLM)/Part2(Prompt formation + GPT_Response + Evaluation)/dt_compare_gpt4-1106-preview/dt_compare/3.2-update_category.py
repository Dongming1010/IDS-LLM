import json

# Define the file path
input_file_path = "dt_compare/updated_matching_predictions_with_prob.json"  # Change this to the path of your input JSON file
output_file_path = "dt_compare/category_updated_matching_predictions_with_prob.json"  # Change this to the desired output file path

# Load the JSON file
with open(input_file_path, 'r') as file:
    data = json.load(file)

# Add 'traffic_type' based on the 'label'
for entry in data:
    if entry['Label'] == 'BenignTraffic':
        entry['traffic_type'] = 'BenignTraffic'
    else:
        entry['traffic_type'] = 'Anomality'
    if entry['gpt_choice'] == 'BenignTraffic':
        entry['gpt_detection'] = 'BenignTraffic'
    else:
        entry['gpt_detection'] = 'Anomality' 

# Save the updated JSON file
with open(output_file_path, 'w') as file:
    json.dump(data, file, indent=4)

print(f"Updated JSON file saved to {output_file_path}")
