import pandas as pd
import json

# Load the CSV files
file1 = 'dt_compare/input/1_5000.csv'
file2 = 'dt_compare/input/2_5000.csv'

df1 = pd.read_csv(file1)
df2 = pd.read_csv(file2)

# Prepare the output dictionary that will later be converted to JSON
output_data = []

# Check if both dataframes have the same length and the required columns
if all(col in df1.columns and col in df2.columns for col in ['prediction', 'label', 'accuracy', 'path']) and len(df1) == len(df2):
    # Compare the 'prediction' column in both dataframes
    differences = df1['prediction'] != df2['prediction']

    # Find row numbers where predictions differ
    differing_rows = differences[differences].index.tolist()

    # Collect data for differing rows where the prediction matches the label
    match_count = 0
    for row in differing_rows:
        if df1.loc[row, 'prediction'] == df1.loc[row, 'label'] or df2.loc[row, 'prediction'] == df2.loc[row, 'label']:
            entry = {
                "Row": row,
                "Label": df1.loc[row, 'label'],
                "Prediction_1": df1.loc[row, 'prediction'],
                "Confidence_1": df1.loc[row, 'accuracy'],
                "Path_1": df1.loc[row, 'path'],
                "Prediction_2": df2.loc[row, 'prediction'],
                "Confidence_2": df2.loc[row, 'accuracy'],
                "Path_2": df2.loc[row, 'path']
            }
            output_data.append(entry)
            match_count += 1

    # Save the output data to a JSON file
    with open('dt_compare/matching_predictions.json', 'w') as file:
        json.dump(output_data, file, indent=4)

    print(f"Data extracted and saved to 'matching_predictions.json'. Total entries: {match_count}")
else:
    print("Error: Files do not have the same structure or required columns missing.")
