import json

# Load the first JSON data
with open('dt_compare/updated_matching_predictions_with_prob.json', 'r') as file:
    first_data = json.load(file)

# Load the second JSON data
with open('dt_compare/input/integrated_data.json', 'r') as file:
    second_data = json.load(file)

# Assuming the data is in list format, create a map from the first data based on 'Row'
first_data_map = {item['Row']: item for item in first_data}

# Define default value for gpt_reason
default_gpt_reason = "Data unavailable for prediction."

# Update second_data based on the first_data map using 'Row' key
for item in second_data:
    row = item['Row']
    if row in first_data_map:
        # Update gpt_choice and gpt_reason if the row exists in first_data_map
        item['gpt_choice'] = first_data_map[row].get('gpt_choice', item['Prediction_1'])
        item['gpt_reason'] = first_data_map[row].get('gpt_reason', default_gpt_reason)
    else:
        # If no matching row, set gpt_choice to the current Prediction_1 and apply default gpt_reason
        item['gpt_choice'] = item['Prediction_2']
        item['gpt_reason'] = default_gpt_reason

# Save the updated data into a new JSON file
with open('dt_compare/output/data_with_prob.json', 'w') as file:
    json.dump(second_data, file, indent=4)

print("The second JSON file has been updated and saved as 'updated_file.json'.")
