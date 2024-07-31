import pandas as pd

# Mapping of old feature names to new descriptive names
feature_descriptions = {
    'ts': "Timestamp",
    'flow_duration': "The Duration of the packet's flow",
    'Header_Length': "Packet header length",
    'Protocol_Type': "Protocol type",
    'Duration': "Time-to-Live",
    'Rate': "Rate of packet transmission",
    'Srate': "Rate of outbound packets transmission",
    'Drate': "Rate of inbound packets transmission",
    'fin_flag_number': "Indication whether FIN flags appear in the traffic (1 for true, 0 otherwise)",
    'syn_flag_number': "Indication whether SYN flags appear in the traffic (1 for true, 0 otherwise)",
    'rst_flag_number': "Indication whether RST flags appear in the traffic (1 for true, 0 otherwise)",
    'psh_flag_number': "Indication whether PSH flags appear in the traffic (1 for true, 0 otherwise)",
    'ack_flag_number': "Indication whether ACK flags appear in the traffic (1 for true, 0 otherwise)",
    'ece_flag_number': "Indication whether ECE flags appear in the traffic (1 for true, 0 otherwise)",
    'cwr_flag_number': "Indication whether CWR flags appear in the traffic (1 for true, 0 otherwise)",
    'ack_count': "Number of packets with an ACK flag",
    'syn_count': "Number of packets with a SYN flag",
    'fin_count': "Number of packets with a FIN flag",
    'urg_count': "Number of packets with an URG flag",
    'rst_count': "Number of packets with an RST flag",
    'HTTP': "Indication whether the application layer protocol is HTTP (1 for true, 0 otherwise)",
    'HTTPS': "Indication whether the application layer protocol is HTTPS (1 for true, 0 otherwise)",
    'DNS': "Indication whether the application layer protocol is DNS (1 for true, 0 otherwise)",
    'Telnet': "Indication whether the application layer protocol is Telnet (1 for true, 0 otherwise)",
    'SMTP': "Indication whether the application layer protocol is SMTP (1 for true, 0 otherwise)",
    'SSH': "Indication whether the application layer protocol is SSH (1 for true, 0 otherwise)",
    'IRC': "Indication whether the application layer protocol is IRC (1 for true, 0 otherwise)",
    'TCP': "Indication whether the transport layer protocol is TCP (1 for true, 0 otherwise)",
    'UDP': "Indication whether the transport layer protocol is UDP (1 for true, 0 otherwise)",
    'DHCP': "Indication whether the application layer protocol is DHCP (1 for true, 0 otherwise)",
    'ARP': "Indication whether the link layer protocol is ARP (1 for true, 0 otherwise)",
    'ICMP': "Indication whether the network layer protocol is ICMP (1 for true, 0 otherwise)",
    'IPv': "Indication whether the network layer protocol is IP (1 for true, 0 otherwise)",
    'LLC': "Indication whether the link layer protocol is LLC (1 for true, 0 otherwise)",
    'Tot_sum': "Total sum of packets lengths",
    'Min': "Minimum packet length in the flow",
    'Max': "Maximum packet length in the flow",
    'AVG': "Average packet length in the flow",
    'Std': "Standard deviation of packet length",
    'Tot_size': "Packet's length",
    'IAT': "The time difference between two consecutive packets",
    'Number': "The total number of packets",
    'Magnitue': "Magnitude (calculated as the mean of the average lengths of incoming and outgoing packets in the flow)",
    'Radius': "Radius (calculated as the averaged variances of packet lengths for incoming and outgoing packets)",
    'Covariance': "Covariance (covariance of the lengths of incoming and outgoing packets)",
    'Variance': "Variance (calculated as the ratio of variances in packet lengths between incoming and outgoing packets)",
    'Weight': "Weight (calculated as the product of the counts of incoming and outgoing packets)"
}

# Load the dataset
df = pd.read_csv('source/5000_data.csv')

flag_count_mapping = {
    'ack_count': 'ack_flag_number',
    'syn_count': 'syn_flag_number',
    'fin_count': 'fin_flag_number',
    'rst_count': 'rst_flag_number'
}

# Make sure the flag existance indication match its count value
for count, flag in flag_count_mapping.items():
    # Set the flag to 0 where count is 0
    df.loc[df[count] == 0, flag] = 0
    df.loc[df[count] == 1, flag] = 1
    
# Rename columns based on the provided mapping
df.rename(columns=feature_descriptions, inplace=True)

df.drop(columns=['Protocol type'], inplace=True)

# Save the modified DataFrame to a new CSV file
df.to_csv('source/renamed_5000_data.csv', index=False)

print("CSV file with renamed features has been saved as 'renamed_features_network_traffic.csv'.")
