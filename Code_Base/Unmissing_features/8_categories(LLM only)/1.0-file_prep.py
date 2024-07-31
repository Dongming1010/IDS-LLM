import json
import pandas as pd

# Load your dataset
df = pd.read_csv('source/renamed_5000_data.csv')

def create_entry(row):
    """Create an entry in the desired format for GPT to determine the category of network traffic."""
    system_prompt = (
        "Your task is to classify the type of network traffic based on the provided features. "
        "Begin your response by stating 'Most likely type of traffic: ' followed by the category name from "
        "['BenignTraffic', 'DDoS', 'Brute_Force', 'Spoofing', 'DoS', 'Recon', 'Web-Based', 'Mirai']. "
        "Then, provide a rationale for your choice, considering the descriptions and any other relevant data provided in the features."
    )
    
    user_prompt = "Based on the following features, what is the most likely type of network traffic? "
    user_prompt += ", ".join(f"{feature}={row[feature]}" for feature in df.columns if feature != 'label')
    
    return [
        {
            "role": "system",
            "content": system_prompt
        }, 
        {
            "role": "user",
            "content": user_prompt
        }
    ]

output_jsonl_path = 'output/network_traffic_classification.jsonl'

# Open the output file in write mode
with open(output_jsonl_path, 'w') as outfile:
    for _, row in df.iterrows():
        json_entry = create_entry(row)
        # Write each entry to the file with a newline
        outfile.write(json.dumps(json_entry) + '\n')

print("JSONL file prepared and saved successfully.")
