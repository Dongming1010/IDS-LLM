import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score
import matplotlib.pyplot as plt
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.tree import _tree
from sklearn.preprocessing import KBinsDiscretizer
import numpy as np
import re
from sklearn.utils import resample
from sklearn.metrics import precision_score, recall_score, f1_score, classification_report

def ndarray_to_formatted_string(ndarray):
    # Convert the NumPy array to a string using array2string, customizing the separator
    string_repr = np.array2string(ndarray, separator=', ')
    # Clean up the string to fit np.array() constructor format for the generated code
    # Remove the leading 'array(' and trailing ')', and replace newlines and multiple spaces
    formatted_string = string_repr.replace('array(', '').replace(')', '').replace('\n', '').replace('      ', ' ')
    return formatted_string.strip()

# Load the dataset
df = pd.read_csv('source/first_50000.csv')
df.rename(columns={'Tot sum': 'Tot_sum'}, inplace=True)
df.rename(columns={'Tot size': 'Tot_size'}, inplace=True)
df.rename(columns={'Protocol Type': 'Protocol_Type'}, inplace=True)

from sklearn.tree import _tree

def tree_to_code(tree, feature_names, target_string, feature_string, filename='tree_code.py'):
    with open(filename, 'w') as file:
        tree_ = tree.tree_
        feature_name = [
            feature_names[i] if i != _tree.TREE_UNDEFINED else "undefined!"
            for i in tree_.feature
        ]
        #print(feature_name)
        feature_names = [f.replace(" ", "_")[:-5] for f in feature_names]
        file.write("#Target Lables:({}):\n".format(target_string))
        file.write("def predict({}):\n".format(feature_string))
        file.write("    dict = {}\n")
        file.write("    threshholds = []\n")

        def recurse(node, depth):
            indent = "    " * depth
            if tree_.feature[node] != _tree.TREE_UNDEFINED:
                name = feature_name[node]
                threshold = tree_.threshold[node]
                file.write("{}if {} <= {}:\n".format(indent, name, np.round(threshold,2)))
                file.write("{}    dict['{}'] = {}\n".format(indent, name, name))
                #file.write("{}    threshholds['{}'] = ['{}', {}]\n".format(indent, name, '<=', np.round(threshold,2)))
                file.write("{}    threshholds.append(['{}', '{}', {}])\n".format(indent, name, '<=', np.round(threshold,2)))
                recurse(tree_.children_left[node], depth + 1)
                file.write("{}else:  # if {} > {}\n".format(indent, name, np.round(threshold,2)))
                file.write("{}    dict['{}'] = {}\n".format(indent, name, name))
                #file.write("{}    threshholds['{}'] = ['{}', {}]\n".format(indent, name, '>', np.round(threshold,2)))
                file.write("{}    threshholds.append(['{}', '{}', {}])\n".format(indent, name, '>', np.round(threshold,2)))
                recurse(tree_.children_right[node], depth + 1)
            else:
                #print(type(tree_.value[node]))
                file.write("{}return {}, dict, threshholds\n".format(indent, ndarray_to_formatted_string(tree_.value[node])))

        recurse(0, 1)

def get_rules(tree, feature_names, class_names):
    tree_ = tree.tree_
    feature_name = [
        feature_names[i] if i != _tree.TREE_UNDEFINED else "undefined!"
        for i in tree_.feature
    ]

    paths = []
    path = []
    
    def recurse(node, path, paths):
        
        if tree_.feature[node] != _tree.TREE_UNDEFINED:
            name = feature_name[node]
            threshold = tree_.threshold[node]
            p1, p2 = list(path), list(path)
            p1 += [f"({name} <= {np.round(threshold, 2)})"]
            recurse(tree_.children_left[node], p1, paths)
            p2 += [f"({name} > {np.round(threshold, 2)})"]
            recurse(tree_.children_right[node], p2, paths)
        else:
            path += [(tree_.value[node], tree_.n_node_samples[node])]
            paths += [path]
            
    recurse(0, path, paths)

    # sort by samples count
    samples_count = [p[-1][1] for p in paths]
    ii = list(np.argsort(samples_count))
    paths = [paths[i] for i in reversed(ii)]
    
    rules = []
    for path in paths:
        rule = "if "
        
        for p in path[:-1]:
            if rule != "if ":
                rule += " and "
            rule += str(p)
        rule += " then "
        if class_names is None:
            rule += "response: "+str(np.round(path[-1][0][0][0],3))
        else:
            classes = path[-1][0][0]
            l = np.argmax(classes)
            # print(l)
            # print(len(class_names))
            rule += f"class: {class_names[l]} (proba: {np.round(100.0*classes[l]/np.sum(classes),2)}%)"
        rule += f" | based on {path[-1][1]:,} samples"
        rules += [rule]
        
    return rules

# Extract feature names (all column names except the last one)
feature_names = df.columns[:-1]
formatted_features = ', '.join(feature_names)
#print(formatted_features)

X = df.iloc[:, :-1]
y = df.iloc[:, -1]
target_name = y.unique()
formatted_targets = ', '.join(target_name)
#print(formatted_targets)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=4000, random_state=2)



# Combine X_test and y_test_df
combined_test = pd.concat([X_test, y_test], axis=1)

# Save the combined DataFrame to a CSV file
combined_test.to_csv('source/dt2_combined_test.csv', index=False)



depth = 9
# 2 77
# 17 78.95
dt_clf = DecisionTreeClassifier(max_depth=depth, max_features='sqrt', random_state=2)
dt_clf.fit(X_train, y_train)

importances = dt_clf.feature_importances_
# print("Feature importances:", importances)

dt_predictions = dt_clf.predict(X_test)
dt_accuracy = accuracy_score(y_test, dt_predictions)
print(f"Depth: {depth} \nAccuracy: {dt_accuracy:.4f}")

y_pred = dt_clf.predict(X_test)
precision = precision_score(y_test, y_pred, average='macro')
recall = recall_score(y_test, y_pred, average='macro')
f1 = f1_score(y_test, y_pred, average='macro')

print("Precision: {:.2f}".format(precision))
print("Recall: {:.2f}".format(recall))
print("F1 Score: {:.2f}".format(f1))

tree_rules = tree_to_code(dt_clf, feature_names, formatted_targets, formatted_features, "code_form/1_code_form_temp.py")

tree_rules = get_rules(dt_clf, feature_names, target_name)
with open(f'natural_language_form/1_decision_tree_rule-{depth}-natrual_language_temp.txt', 'w') as file:
    for line in tree_rules:
        # Write each string to a new line in the text file
        file.write(line + '\n')
        
feature_names = X.columns
tree_rules = export_text(dt_clf, feature_names=list(feature_names))
with open(f'rules&thresholds/decision_tree_rule-{depth}_2rd_temp.txt', 'w') as file:
    file.write(tree_rules)
    
print("Saved")
