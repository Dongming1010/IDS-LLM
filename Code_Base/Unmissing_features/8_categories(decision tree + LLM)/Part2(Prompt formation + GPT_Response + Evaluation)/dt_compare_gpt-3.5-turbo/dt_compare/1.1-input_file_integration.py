import pandas as pd
import json

# Load the CSV files
file1 = 'dt_compare/input/1_5000.csv'
file2 = 'dt_compare/input/2_5000.csv'

# Read the CSV files into pandas DataFrames
df1 = pd.read_csv(file1)
df2 = pd.read_csv(file2)

# Prepare the output list to store the integrated data from both files
output_data = []

# Ensure that both DataFrames have the same length
if len(df1) == len(df2):
    # Iterate over rows by index assuming both dataframes align by row index
    for idx in df1.index:
        entry = {
            "Row": idx,
            "Label": df1.loc[idx, 'label'],
            "Prediction_1": df1.loc[idx, 'prediction'],
            "Accuracy_1": df1.loc[idx, 'accuracy'],
            "Path_1": df1.loc[idx, 'path'],
            "Prediction_2": df2.loc[idx, 'prediction'],
            "Accuracy_2": df2.loc[idx, 'accuracy'],
            "Path_2": df2.loc[idx, 'path']
        }
        output_data.append(entry)

    # Save the integrated data to a JSON file
    with open('dt_compare/input/integrated_data.json', 'w') as file:
        json.dump(output_data, file, indent=4)

    print("Integrated data from both CSV files has been extracted and saved to 'integrated_data.json'.")
else:
    print("Error: The files do not have the same length.")
