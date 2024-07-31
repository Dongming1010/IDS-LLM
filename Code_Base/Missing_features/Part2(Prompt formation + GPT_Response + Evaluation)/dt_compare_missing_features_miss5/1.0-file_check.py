import json

with open('dt_compare_missing_features_miss5/output/analysis_input_results_without_prob.json', 'r') as file:
    data = json.load(file)

matching_rates = []
# path_1_2 = []
# path_3_7 = []
# path_8_11 = []
# path_12_15 = []
# path_16 = []
# path_total = []
# count = 0
path_1_2 = []
path_3_5 = []
path_6_8 = []
path_9_11 = []
path_12_14 = []
path_15 = []
path_total = []
count = 0

life = []
num = 0
for item in data:
    label = item[1]
    len1 = len(item[2]["first_tree"])
    len2 = len(item[2]["second_tree"])
    matching_count = 0
    for path in item[2]["first_tree"]:
        if (path[2] == label):
            matching_count += 1
    for path in item[2]["second_tree"]:
        if (path[2] == label):
            matching_count += 1
    total = len1 + len2
    gpt = item[3]
    # print(gpt + "  "  + label)
    if (gpt == label):
        count += 1
    if (total <= 2):
        life.append(matching_count / (total))
        # print(num)
        if (gpt == label):
            path_1_2.append(True)
        else:
            path_1_2.append(False)
    elif (total <= 5):
        if (gpt == label):
            path_3_5.append(True)
        else:
            path_3_5.append(False)
    elif (total <= 8):
        if (gpt == label):
            path_6_8.append(True)
        else:
            path_6_8.append(False)     
    elif (total <= 11):
        if (gpt == label):
            path_9_11.append(True)
        else:
            path_9_11.append(False)
    elif (total <= 14):
        if (gpt == label):
            path_12_14.append(True)
        else:
            path_12_14.append(False)
    else:
        if (gpt == label):
            path_15.append(True)
        else:
            path_15.append(False)
     
    if (gpt == label):
        path_total.append(True)
    else:
        path_total.append(False)   
    num += 1
    matching_rates.append(matching_count / (total))
    
# print("Accuracy for " + str(sum(life) / len(life)))
print(f"Accuracy for 1-2 paths({len(path_1_2)}): " + str(sum(path_1_2) / len(path_1_2)))  
print(f"Accuracy for 3-5 paths({len(path_3_5)}): " + str(sum(path_3_5) / len(path_3_5)))
print(f"Accuracy for 6-8 paths({len(path_6_8)}): " + str(sum(path_6_8) / len(path_6_8)))
print(f"Accuracy for 9-11 paths({len(path_9_11)}): " + str(sum(path_9_11) / len(path_9_11)))
print(f"Accuracy for 12-14 paths({len(path_12_14)}): " + str(sum(path_12_14) / len(path_12_14)))
print(f"Accuracy >=15 paths({len(path_15)}): " + str(sum(path_15) / len(path_15)))
print(f"Total accuracy paths({count} / {len(path_total)}): " + str(sum(path_total) / len(path_total)))
# print(sum(matching_rates) / len(matching_rates))