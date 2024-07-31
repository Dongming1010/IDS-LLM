import json

def create_entry(row, prediction1, path1, prediction2, path2):
    """Create an entry in the desired format for GPT to determine which prediction is better."""
    return [
        {
            "role": "system",
            "content": f"Your task is to evaluate 2 decision paths from two different decision trees analyzing network traffic data, each supported by a decision tree path. Begin your response by stating the most likely type of traffic starting with 'Most likely type of traffic: ' and choose exactly from ['Benign', 'Threat']. Then, specify 'The most plausible path is from the first tree' or 'The most plausible path is from the second tree', depending on which path from which tree you believe provides the most accurate explanation based on the path descriptions. Provide a rationale for your choice, considering the descriptions and any other relevant data provided in the paths."
        },
        {
            "role": "user",
            "content": f"Please evaluate the following two different paths, each generated by a different decision tree, and choose the single path that makes the most sense based on the descriptions and predictions. Provide reasons for your choice:\nPath from first_tree:\nPath Description: {path1}\nPrediction result for above path description: {prediction1}\nPath from second_tree:\nPath Description: {path2}\nPrediction result for above path description: {prediction2}"
        }
    ]

input_json_path = 'dt_compare_benign_threat_3.5_16k/input/matching_integrated_data.json'
output_jsonl_path = 'dt_compare_benign_threat_3.5_16k/output/analysis_input_without_prob.jsonl'  # Notice the .jsonl extension

# Load the JSON data from the file
with open(input_json_path, 'r') as file:
    data = json.load(file)

# Open the output file in write mode
with open(output_jsonl_path, 'w') as outfile:
    for entry in data:
        #print(entry[1])
        json_entry = create_entry(
            row=entry[0],
            prediction1=entry[2]['first_tree'][0][0][2],
            path1=entry[2]['first_tree'][0][0][1],
            prediction2=entry[2]['second_tree'][0][0][2],
            path2=entry[2]['second_tree'][0][0][1]
        )
        # Convert the entry to a JSON string and write it to the file with a newline
        outfile.write(json.dumps(json_entry) + '\n')

print("File prepared for analysis and saved successfully.")
