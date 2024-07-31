import json
import pandas as pd

# Load your dataset
df = pd.read_csv('source/renamed_5000_data.csv')

def create_entry(row):
    """Create an entry in the desired format for GPT to determine the category of network traffic."""
    system_prompt = (
        "Your task is to classify the type of network traffic based on the provided features. "
        "Let's think step by step through the reasoning for your choice, considering the descriptions "
        "and any other relevant data provided in the features. "
        "After completing your analysis, conclude your response by using the phrase 'Most likely type of traffic: ' followed immediately by your chosen category, "
        "ensuring the category name is exactly as listed: ['BenignTraffic', 'DDoS', 'Brute_Force', 'Spoofing', 'DoS', 'Recon', 'Web-Based', 'Mirai']. "
        "This should be the last phrase in your response. "
    )

    user_prompt = "Let's think step by step. Based on the following features, what is the most likely type of network traffic?"
    user_prompt += ", ".join(f"{feature}={row[feature]}" for feature in df.columns if feature != 'label' and feature != 'Protocol Type')
    
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

output_jsonl_path = 'output/network_traffic_classification_CoT.jsonl'

# Open the output file in write mode
with open(output_jsonl_path, 'w') as outfile:
    for _, row in df.iterrows():
        json_entry = create_entry(row)
        # Write each entry to the file with a newline
        outfile.write(json.dumps(json_entry) + '\n')

print("JSONL file prepared and saved successfully.")
