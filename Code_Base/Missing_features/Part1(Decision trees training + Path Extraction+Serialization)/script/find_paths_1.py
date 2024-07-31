import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score
import matplotlib.pyplot as plt
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.tree import _tree
from sklearn.preprocessing import KBinsDiscretizer
import numpy as np
import re
import random

# Script Outline
# Input: row
# Output: paths(num >=1)
# For each paths, there should be (prediction, accuracy, the missing features)
# Note: There should be a measture for the missing features
#       Broken Path(features all missing) should be handled
random.seed(42)

numerical_features = [
    'flow_duration', 'Header_Length', 'Duration', 'Rate',
    'Srate', 'Drate', 'ack_count','syn_count','fin_count','urg_count',
    'rst_count','Tot_sum', 'Min', 'Max', 'AVG', 'Std',
    'Tot_size', 'IAT', 'Number', 'Magnitue', 'Radius',
    'Covariance', 'Variance', 'Weight'
]

flag_features = [
    'HTTP', 'HTTPS', 'DNS', 'Telnet',
    'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP',
    'ICMP', 'IPv', 'LLC'
]

all_features = [
    'flow_duration', 'Header_Length', 'Duration', 'Rate',
    'Srate', 'Drate', 'ack_count','syn_count','fin_count','urg_count',
    'rst_count','Tot_sum', 'Min', 'Max', 'AVG', 'Std',
    'Tot_size', 'IAT', 'Number', 'Magnitue', 'Radius',
    'Covariance', 'Variance', 'Weight',
    'HTTP', 'HTTPS', 'DNS', 'Telnet',
    'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP',
    'ICMP', 'IPv', 'LLC'
]

# Generate a list of 5000 elements, each element is a tuple of 3 random numbers from 1 to 23
random_list = [random.sample(range(38), 11) for _ in range(5000)]
removement_flag_list = []
idx = 0

df = pd.read_csv('source/full_dataset.csv')
df = df.groupby('label').sample(n=625, random_state=42)
df.rename(columns={'Tot sum': 'Tot_sum'}, inplace=True)
df.rename(columns={'Tot size': 'Tot_size'}, inplace=True)
df.rename(columns={'Protocol Type': 'Protocol_Type'}, inplace=True)