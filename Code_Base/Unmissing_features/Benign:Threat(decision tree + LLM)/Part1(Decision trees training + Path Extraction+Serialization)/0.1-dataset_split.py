import pandas as pd

df = pd.read_csv('source/binary_dataset.csv')
df = df.groupby('label').sample(n=13000, random_state=42)
# Sample the first 6250 rows per label from df
first = df.groupby('label').sample(n=6150, random_state=42)

# Define second as the next 6250 rows per label after taking out first
second = df[~df.index.isin(first.index)].groupby('label').sample(n=6150, random_state=42)

# Define third as the remaining rows after taking out rows in first and second
third = df[~df.index.isin(first.index.append(second.index))]

label_counts = first['label'].value_counts()

print(label_counts)

label_counts = second['label'].value_counts()

print(label_counts)

df_shuffled = third.sample(frac=1).reset_index(drop=True)

# Save the shuffled DataFrame to a new CSV file
first.to_csv('source/first.csv', index=False)
second.to_csv('source/second.csv', index=False)
df_shuffled.to_csv('source/test.csv', index=False)