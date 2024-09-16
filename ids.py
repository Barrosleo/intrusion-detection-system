pip install scikit-learn pandas numpy scapy

import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Load and Prepare the Dataset
def load_data(file_path):
    data = pd.read_csv(file_path)
    # Preprocess the data as needed
    return data

data = load_data('kddcup.data_10_percent_corrected')
X = data.drop(['label'], axis=1)
y = data['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train the Machine Learning Model (Random Forest classifier)
def train_model(X_train, y_train):
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    return model

model = train_model(X_train, y_train)

# Evaluate the Model
def evaluate_model(model, X_test, y_test):
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model Accuracy: {accuracy * 100:.2f}%")

evaluate_model(model, X_test, y_test)

# Capture and Analyze Network Traffic
def packet_callback(packet):
    if IP in packet and TCP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport
        # Extract features and predict
        features = np.array([[ip_src, ip_dst, tcp_sport, tcp_dport]])
        prediction = model.predict(features)
        if prediction == 'anomaly':
            print(f"Alert! Suspicious activity detected from {ip_src} to {ip_dst}")

sniff(filter="ip", prn=packet_callback, store=0)

