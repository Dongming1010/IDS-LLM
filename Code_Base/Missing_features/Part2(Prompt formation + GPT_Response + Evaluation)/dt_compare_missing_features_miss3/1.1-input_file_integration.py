import json

with open('dt_compare_missing_features_miss3/input/dt_1_3_missing.json', 'r') as file:
    list1 = json.load(file)
with open('dt_compare_missing_features_miss3/input/dt_2_3_missing.json', 'r') as file:
    list2 = json.load(file)
    
# Prepare the output list to store the integrated data from both files
output_data = []
idx = 0

def remove_duplicates(data):
    seen = set()
    unique_data = []

    for item in data:
        # Convert the item to a JSON string, which is hashable and allows for comparison
        item_string = json.dumps(item, sort_keys=True)
        if item_string not in seen:
            unique_data.append(item)
            seen.add(item_string)

    return unique_data

# Ensure that both DataFrames have the same length
for item1, item2 in zip(list1, list2):
    label = item1[0]
    check = False
    path_1 = item1[1]
    path_2 = item2[1]
    set1 = set()
    set2 = set()
    ##check at least match one path
    for entry1 in path_1:
        set1.add(entry1[2])
        if entry1[2] == label:
            check = True
    for entry2 in path_2:
        set2.add(entry2[2])
        if entry2[2] == label:
            check = True
    
    if check == True and (len(set1) > 1 or len(set2) > 1 or set1.isdisjoint(set2)) and (len(set1) != 0 and len(set2) != 0):
        dict = {
            "first_tree" : remove_duplicates(path_1),
            "second_tree" : remove_duplicates(path_2)
        }
        output_data.append([idx, label, dict])
    idx += 1
with open('dt_compare_missing_features_miss3/input/matching_integrated_data.json', 'w') as file:
    json.dump(output_data, file, indent=4)
    