# loading the dataset for our project
# CICIDS2017 cleaned version

import pandas as pd
import numpy as np
import warnings
warnings.filterwarnings('ignore')

print("loading dataset please wait...")

# read the csv file
data = pd.read_csv('data/cicids2017_cleaned.csv')

print("dataset loaded")
print("number of rows :", data.shape[0])
print("number of columns :", data.shape[1])

# check what columns we have
print("\ncolumn names in dataset :")
for col in data.columns:
    print(" -", col)

# find the label column
label_column = None
for col in data.columns:
    if 'attack' in col.lower() or 'label' in col.lower():
        label_column = col
        break

# show attack types
if label_column:
    print("\nattack types found :")
    print(data[label_column].value_counts())
else:
    print("label column not found")
    print("columns are :", data.columns.tolist())

# show sample data
print("\nfirst 5 rows :")
print(data.head(5))

print("\ndone with step 1")