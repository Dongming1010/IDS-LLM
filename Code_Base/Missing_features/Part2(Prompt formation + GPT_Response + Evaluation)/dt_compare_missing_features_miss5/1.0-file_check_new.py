import json
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from collections import Counter

with open('dt_compare_missing_features_miss5/output/analysis_input_results_without_prob.json', 'r') as file:
    data = json.load(file)

matching_rates = []

path_1_2_label = []
path_3_5_label = []
path_6_8_label = []
path_9_11_label = []
path_12_14_label = []
path_15_label = []

path_1_2_prediction = []
path_3_5_prediction = []
path_6_8_prediction = []
path_9_11_prediction = []
path_12_14_prediction = []
path_15_prediction = []

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
        path_1_2_prediction.append(gpt)
        path_1_2_label.append(label)
    elif (total <= 5):
        if (gpt == label):
            path_3_5.append(True)
        else:
            path_3_5.append(False)
        path_3_5_prediction.append(gpt)
        path_3_5_label.append(label)
    elif (total <= 8):
        if (gpt == label):
            path_6_8.append(True)
        else:
            path_6_8.append(False)
        path_6_8_prediction.append(gpt)
        path_6_8_label.append(label)   
    elif (total <= 11):
        if (gpt == label):
            path_9_11.append(True)
        else:
            path_9_11.append(False)
        path_9_11_prediction.append(gpt)
        path_9_11_label.append(label)
    elif (total <= 14):
        if (gpt == label):
            path_12_14.append(True)
        else:
            path_12_14.append(False)
        path_12_14_prediction.append(gpt)
        path_12_14_label.append(label)
    else:
        if (gpt == label):
            path_15.append(True)
        else:
            path_15.append(False)
        path_15_prediction.append(gpt)
        path_15_label.append(label)
     
    if (gpt == label):
        path_total.append(True)
    else:
        path_total.append(False)   
    num += 1
    matching_rates.append(matching_count / (total))
    
def calculate_scores(actual_labels, predictions):
    """
    Calculate accuracy, precision, recall, and F1 score for the provided labels and predictions.
    Handles the case where metrics may be ill-defined due to absent classes in predictions or labels,
    and handles empty input lists by returning None for all metrics.
    
    :param actual_labels: List or array of actual labels
    :param predictions: List or array of predicted labels
    :return: Dictionary with accuracy, precision, recall, and F1 score
    """
    if len(actual_labels) == 0 or len(predictions) == 0:
        return {'accuracy': None, 'precision': None, 'recall': None, 'f1': None}

    try:
        scores = {
            'accuracy': accuracy_score(actual_labels, predictions),
            'precision': precision_score(actual_labels, predictions, average='macro', zero_division=0),
            'recall': recall_score(actual_labels, predictions, average='macro', zero_division=0),
            'f1': f1_score(actual_labels, predictions, average='macro', zero_division=0)
        }
    except ValueError as e:
        print(f"Error calculating scores: {e}")
        scores = {'accuracy': None, 'precision': None, 'recall': None, 'f1': None}
    return scores

# Labels and predictions grouped by paths
path_groups = {
    'path 1_2': (path_1_2_label, path_1_2_prediction),
    'path 3_5': (path_3_5_label, path_3_5_prediction),
    'path 6_8': (path_6_8_label, path_6_8_prediction),
    'path 9_11': (path_9_11_label, path_9_11_prediction),
    'path 12_14': (path_12_14_label, path_12_14_prediction),
    'path 15': (path_15_label, path_15_prediction)
}

# Iterate through each path group
for path_name, (actual, pred) in path_groups.items():
    scores = calculate_scores(actual, pred)
    if all(value is None for value in scores.values()):
        print(f"Scores for {path_name}({len(actual)}): No data available.")
    else:
        print(f"Scores for {path_name}({len(actual)}): {scores}.")
    
labels = [
    path_1_2_label, path_3_5_label, path_6_8_label,
    path_9_11_label, path_12_14_label, path_15_label
]
predictions = [
    path_1_2_prediction, path_3_5_prediction, path_6_8_prediction,
    path_9_11_prediction, path_12_14_prediction, path_15_prediction
]

# combined_data = (path_1_2_label + path_3_5_label + path_6_8_label +
#                  path_9_11_label + path_12_14_label + path_15_label +
#                  path_1_2_prediction + path_3_5_prediction + path_6_8_prediction +
#                  path_9_11_prediction + path_12_14_prediction + path_15_prediction)

# # Calculate the variation across the combined data of actual labels and predictions
# overall_variation = Counter(combined_data)

# # Print the combined variations in actual labels and predictions
# print("Combined variation in actual labels and predictions across all groups:", dict(overall_variation))

# # print("Accuracy for " + str(sum(life) / len(life)))
# print(f"Accuracy for 1-2 paths({len(path_1_2)}): " + str(sum(path_1_2) / len(path_1_2)))  
# print(f"Accuracy for 3-5 paths({len(path_3_5)}): " + str(sum(path_3_5) / len(path_3_5)))
# print(f"Accuracy for 6-8 paths({len(path_6_8)}): " + str(sum(path_6_8) / len(path_6_8)))
# print(f"Accuracy for 9-11 paths({len(path_9_11)}): " + str(sum(path_9_11) / len(path_9_11)))
# print(f"Accuracy for 12-14 paths({len(path_12_14)}): " + str(sum(path_12_14) / len(path_12_14)))
# print(f"Accuracy >=15 paths({len(path_15)}): None")
# print(f"Total accuracy paths({count} / {len(path_total)}): " + str(sum(path_total) / len(path_total)))
# # print(sum(matching_rates) / len(matching_rates))