# training the xgboost model on cicids2017 dataset
# this file prepares data and trains the classifier

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, classification_report
import pickle
import warnings
warnings.filterwarnings('ignore')

print("loading dataset...")
data = pd.read_csv('data/cicids2017_cleaned.csv')
print("rows :", data.shape[0])
print("columns :", data.shape[1])

# separate features and target
target_col = 'Attack Type'
x = data.drop(target_col, axis=1)
y = data[target_col]

print("\nattack types :")
print(y.value_counts())

# encode labels to numbers
encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)

print("\nencoded labels :")
for i, name in enumerate(encoder.classes_):
    print(i, "=", name)

# scale the features
print("\nscaling features...")
scaler = StandardScaler()
x_scaled = scaler.fit_transform(x)

# split into train and test
x_train, x_test, y_train, y_test = train_test_split(
    x_scaled, y_encoded,
    test_size=0.2,
    random_state=42
)

print("train size :", x_train.shape[0])
print("test size  :", x_test.shape[0])

# train xgboost model
print("\ntraining model please wait...")
model = XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    random_state=42,
    eval_metric='mlogloss'
)
model.fit(x_train, y_train)
print("model training done!")

# test the model
print("\ntesting model...")
y_pred = model.predict(x_test)

# show results
acc = accuracy_score(y_test, y_pred) * 100
print("\n===== MODEL RESULTS =====")
print("accuracy :", round(acc, 2), "%")
print("\ndetailed report :")
print(classification_report(
    y_test, y_pred,
    target_names=encoder.classes_
))

# save model and tools
print("saving model...")
with open('models/model.pkl', 'wb') as f:
    pickle.dump(model, f)

with open('models/encoder.pkl', 'wb') as f:
    pickle.dump(encoder, f)

with open('models/scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)

print("model saved to models folder")
print("\ndone with step 2!")