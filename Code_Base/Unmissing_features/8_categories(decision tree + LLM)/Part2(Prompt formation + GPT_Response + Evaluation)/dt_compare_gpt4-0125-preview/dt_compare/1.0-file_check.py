import pandas as pd

# Load the CSV files
file1 = 'dt_compare/input/1_5000.csv'
file2 = 'dt_compare/input/2_5000.csv'

df1 = pd.read_csv(file1)
df2 = pd.read_csv(file2)

# Open a text file to write the output
with open('dt_compare/differences_output.txt', 'w') as output_file:
    # Check if both dataframes have the same length and the required columns
    if all(col in df1.columns and col in df2.columns for col in ['prediction', 'label', 'accuracy']) and len(df1) == len(df2):
        # Compare the 'prediction' column in both dataframes
        differences = df1['prediction'] != df2['prediction']

        # Find row numbers where predictions differ
        differing_rows = differences[differences].index.tolist()

        # Initialize the counter for entries where at least one prediction matches the label
        match_label_count = 0

        # Write the count of differing predictions and detailed differences to the file
        output_file.write(f"Number of differing predictions: {len(differing_rows)}\n")
        if differing_rows:
            output_file.write("Rows with differing predictions:\n")
            output_file.write("{:<10} {:<20} {:<10} {:<20} {:<10} {:<15}\n".format(
                "Row", "Prediction 1", "Accuracy 1", "Prediction 2", "Accuracy 2", "Label"))
            for row in differing_rows:
                prediction1_matches = df1.loc[row, 'prediction'] == df1.loc[row, 'label']
                prediction2_matches = df2.loc[row, 'prediction'] == df2.loc[row, 'label']
                if prediction1_matches or prediction2_matches:
                    match_label_count += 1

                output_file.write("{:<10} {:<20} {:<10} {:<20} {:<10} {:<15}\n".format(
                    row + 1, 
                    df1.loc[row, 'prediction'], 
                    df1.loc[row, 'accuracy'], 
                    df2.loc[row, 'prediction'], 
                    df2.loc[row, 'accuracy'], 
                    df1.loc[row, 'label']))

            # Write the count of entries where at least one prediction matches the label to the file
            output_file.write(f"\nNumber of entries where at least one prediction matches the label: {match_label_count}\n")
    else:
        output_file.write("Error: Files do not have the same structure or required columns missing.\n")
