def parse_condition(condition):
    if '<=' in condition:
        operator = '<='
    elif '>' in condition:
        operator = '>'
    else:
        operator = '<'

    parts = condition.split(operator)
    feature = parts[0].strip()
    value = parts[1].strip()

    feature = feature.replace('(', '').replace(')', '')

    return f"((data['{feature}'] {operator} {value} or (data['{feature}'] == -1))", feature

def parse_rule(rule):
    condition_part = rule.split('then')[0].strip('if').strip()
    outcome_part = rule.split('then')[1]

    class_name = outcome_part.split('(')[0].split(':')[1].strip()
    probability = outcome_part.split('proba: ')[1].split('%')[0].strip()

    conditions = condition_part.split('and')
    parsed_conditions = [parse_condition(cond.strip()) for cond in conditions]
    condition_statements = [cond[0] for cond in parsed_conditions if cond[0] is not None]
    features_used = [cond[1] for cond in parsed_conditions if cond[1] is not None]

    return condition_statements, features_used, class_name, probability

def generate_python_code(rules):
    python_code = "def classify(data):\n"
    python_code += "    global all_entries_res\n"
    python_code += "    potential_paths = []\n"
    for i, rule in enumerate(rules):
        conditions, features_used, class_name, probability = parse_rule(rule)
        #check dup
        seen_features = set()
        ordered_features = []
        for feature in features_used:
            if feature not in seen_features:
                seen_features.add(feature)
                ordered_features.append(feature)
                                                          
        features_dict = ", ".join([f"'{feature}': data['{feature}']" for feature in ordered_features])
        if_statement = "    if " + " and ".join(conditions) + ":\n"
        if_statement += f"        feature_dict = {{{features_dict}}}\n"
        if_statement += f"        potential_paths.append([feature_dict, '{class_name}', {probability}])\n"
        #if_statement += f"        return feature_dict, '{class_name}', {probability}\n"
        python_code += if_statement
    python_code += "    all_entries_res.append(potential_paths)\n"
    python_code += "    return None\n"
    # python_code += "    return {}, 'Unknown', 0  # Default case if no conditions are met\n"
    return python_code

def main():
    with open("natural_language_form/1_decision_tree_rule-9-natrual_language.txt", "r") as file:
        rules = file.readlines()
    
    python_code = generate_python_code(rules)
    
    with open("code_form/1_code_form.py", "w") as output_file:
        output_file.write(python_code)
    print("Python code successfully written to code_form_v2/2_code_form.py")

if __name__ == "__main__":
    main()
