import re
from collections import defaultdict

def extract_thresholds_from_rules(rules):

    feature_thresholds = defaultdict(set)
    
    rule_pattern = re.compile(r"(\w[\w\s]+) *([<>=]+) *([\d.]+)")
    
    for line in rules.split('\n'):
        match = rule_pattern.search(line)
        if match:
            feature, operator, value = match.groups()
            feature = feature.strip()
            value = float(value)
            feature_thresholds[feature].add(value)
    
    for feature in feature_thresholds:
        feature_thresholds[feature] = sorted(feature_thresholds[feature])
    
    return dict(feature_thresholds)

with open('rules&thresholds/2_decision_tree_rule-9_17rd.txt', 'r') as file:
    rules = file.read()

thresholds = extract_thresholds_from_rules(rules)
with open('rules&thresholds/2_thresholds_output-9_17rd.txt', 'w') as out_file:  
    for feature, threshold in thresholds.items():
        output_line = f"{feature}: {threshold}\n"
        print(output_line, end='') 
        out_file.write(output_line) 