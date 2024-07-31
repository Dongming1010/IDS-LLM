import json

def format_path(description, prediction):
    return f"Path_Description: {description}\nPrediction result for above path description: {prediction}"

def generate_query(data):
    queries = []

    index, overall_prediction, trees = data  # assuming each entry is structured as [index, overall_prediction, {trees}]
    for tree_name, paths in trees.items():
        path_descriptions = []
        for path in paths:
            features, description, prediction, probability = path  # Make sure to extract probability if it's unused
            path_desc = format_path(description, prediction)
            path_descriptions.append(path_desc)
    
        queries.append(f"Paths from {tree_name}:\n" + "\n".join(path_descriptions))
    
    full_query = "Please evaluate the following diferent paths generate from 2 different decision tree and choose a single path that makes the most sense based on the descriptions and predictions. Provide reasons for your choice:\n" + "\n\n".join(queries)
    return full_query

def create_entry(data):
    """Create an entry for the JSONL output from given data."""
    query_text = generate_query(data)
    return [
        {
            "role": "system",
            "content": "Your task is to evaluate decision paths from two different decision trees analyzing network traffic data, noting that missing features are marked as 'unknown'. If a given tree Begin your response by stating the most likely type of traffic start by 'Most likely type of traffic: ' and choose exactly from ['BenignTraffic', 'DDoS', 'Brute_Force', 'Spoofing', 'DoS', 'Recon', 'Web-Based', 'Mirai']. Then, specify 'The most plausible path is from [path number] of the first tree' or 'The most plausible path is from [path number] of second tree', note that each tree could have several different paths cause of the missing features choose the path that make most sense for you, depending on which path from which tree you believe provides the most accurate explanation based on the path descriptions where missing features are noted as 'unknown' if there is a missing feature. Provide a rationale for your choice, considering the descriptions and any other relevant data provided in the paths. \nBelow are the brief definitions for each category.\nBenignTraffic: Network traffic that is legitimate and poses no threat to the network's security.\nDDoS (Distributed Denial of Service): An attack where multiple compromised systems flood a target with traffic, overwhelming its resources and causing a denial of service.\nBrute_Force: An attack method where an attacker systematically tries all possible combinations of passwords or encryption keys to gain unauthorized access.\nSpoofing: An attack in which a person or program successfully masquerades as another by falsifying data, to gain an illegitimate advantage.\nDoS (Denial of Service): An attack that aims to make a network service unavailable to its intended users by overwhelming it with a flood of illegitimate requests.\nRecon (Reconnaissance): The process of gathering information about a network to identify potential vulnerabilities before launching an attack.\nWeb-Based: Attacks that exploit vulnerabilities in web applications, such as SQL injection, cross-site scripting, or other methods to compromise a website.\nMirai: A malware that infects networked devices, turning them into a botnet to conduct large-scale attacks like DDoS."
        },
        {
            "role": "user",
            "content": query_text
        }
    ]

input_json_path = 'dt_compare_missing_features_miss7/input/matching_integrated_data.json'
output_jsonl_path = 'dt_compare_missing_features_miss7/output/analysis_input.jsonl'  # Notice the .jsonl extension

# Load the JSON data from the file
with open(input_json_path, 'r') as file:
    data = json.load(file)

# Open the output file in write mode
with open(output_jsonl_path, 'w') as outfile:
    for entry in data:
        json_entry = create_entry(
            entry
        )
        # Convert the entry to a JSON string and write it to the file with a newline
        outfile.write(json.dumps(json_entry) + '\n')

# python parallel_request.py dt_compare_missing_features/output/analysis_input.jsonl dt_compare_missing_features/output/analysis_input_results.jsonl  
# print("File prepared for analysis and saved successfully.")
# input_json_path = 'dt_compare_missing_features/input/matching_integrated_data_temp.json'
# output_json_path = 'dt_compare_missing_features/output/analysis_input.json'  # Changed to .json extension

# # Load the JSON data from the file
# with open(input_json_path, 'r') as file:
#     data = json.load(file)

# # Prepare the list of entries
# entries = []
# for entry in data:
#     json_entry = create_entry(entry)
#     entries.append(json_entry)

# # Open the output file in write mode and write the entire list as a JSON object
# with open(output_json_path, 'w') as outfile:
#     json.dump(entries, outfile, indent=4)  # Optional: add indent for pretty-printing

# print("File prepared for analysis and saved successfully.")
