import json

with open('dt_compare_missing_features_miss7/input/dt_1_7_missing.json', 'r') as file:
    list1 = json.load(file)
with open('dt_compare_missing_features_miss7/input/dt_2_7_missing.json', 'r') as file:
    list2 = json.load(file)
    
# Prepare the output list to store the integrated data from both files
output_data = []
idx = 0

# Ensure that both DataFrames have the same length
for item1, item2 in zip(list1, list2):
    label = item1[0]
    path_1 = item1[1]
    path_2 = item2[1]

    dict = {
        "first_tree" : path_1,
        "second_tree" : path_2
    }
    output_data.append([idx, label, dict])
    idx += 1
with open('dt_compare_missing_features_miss7/input/integrated_data.json', 'w') as file:
    json.dump(output_data, file, indent=4)