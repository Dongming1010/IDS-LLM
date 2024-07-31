import json

# Load the first JSON data
with open('dt_compare_missing_features_miss5/output/analysis_input_results_without_prob.json', 'r') as file:
    first_data = json.load(file)

# Load the second JSON data
with open('dt_compare_missing_features_miss5/input/integrated_data.json', 'r') as file:
    second_data = json.load(file)

# Assuming the data is in list format, create a map from the first data based on 'Row'
first_data_map = [entry[0] for entry in first_data]
# Define default value for gpt_reason
default_gpt_reason = "Data unavailable for prediction."

# Update second_data based on the first_data map using 'Row' key
for item in second_data:
    row = item[0]
    if row in first_data_map:
        # Update gpt_choice and gpt_reason if the row exists in first_data_map
        item.append(first_data[first_data_map.index(row)][3])
        print(row)
        item.append(first_data[first_data_map.index(row)][4])
    else:
        # If no matching row, set gpt_choice to the current Prediction_1 and apply default gpt_reason
        #print(item[2]["first_tree"][0][2])
        item.append(item[2]["first_tree"][0][2])
        item.append(default_gpt_reason)

# Save the updated data into a new JSON file
with open('dt_compare_missing_features_miss5/output/final_data_without_prob.json', 'w') as file:
    json.dump(second_data, file, indent=4)

print("The second JSON file has been updated and saved as 'updated_file.json'.")
