import pandas as pd

# Load the dataset
df = pd.read_csv('source/full_dataset.csv')

# Filter 15 random samples from each category
sampled_df = df.groupby('label').apply(lambda x: x.sample(n=15)).reset_index(drop=True)

# Write the sampled data to a new CSV file
sampled_df.to_csv('source/120_data.csv', index=False)

print("Sampled data has been saved to '120_data.csv'.")
