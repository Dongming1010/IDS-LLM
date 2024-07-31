import pandas as pd

# Load the CSV file
data = pd.read_csv('source/full_dataset.csv')

# Define the function to assign the new label
def assign_type(label):
    if label == 'BenignTraffic':
        return 'Benign'
    else:
        return 'Threat'

# Apply the function to create the new 'Type' column
data['Type'] = data['label'].apply(assign_type)

# Remove the original 'label' column
data.drop('label', axis=1, inplace=True)

# Rename the 'Type' column back to 'label'
data.rename(columns={'Type': 'label'}, inplace=True)

label_counts = data['label'].value_counts()
print(label_counts)

# Save the updated DataFrame to a new CSV file
data.to_csv('source/binary_dataset.csv', index=False)
