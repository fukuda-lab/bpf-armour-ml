import tensorflow as tf
from tensorflow.python.client import device_lib 
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.utils import to_categorical
import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix

print(tf.test.is_built_with_cuda())

# Start of Code
input_file = 'train-dataset.csv'
print('Reading input file')
df = pd.read_csv(input_file)


df[' Label'] = df[' Label'].astype(str)
y=df[' Label']

le = LabelEncoder()
y_encoded = le.fit_transform(y)  # y is your string labels

print(le.classes_)  # Just to confirm the mapping, e.g., ['benign' 'malicious']

y = to_categorical(y_encoded)

df = df.drop(' Label', axis=1)
df = df.drop('Flow ID', axis=1)
df = df.drop(' Source IP', axis=1)
df = df.drop(' Destination IP', axis=1)
df = df.drop([" Source Port", " Destination Port", " Protocol"], axis=1)

X=df.values[:,1:56]
FEATURES = df.columns
FEATURES = FEATURES[1:56]

X = tf.cast(X, dtype=tf.float32)
data_min = tf.reduce_min(X, axis=0)
data_max = tf.reduce_max(X, axis=0)
epsilon = tf.constant(1e-8, dtype=tf.float32)

# Min-Max Normalization
X = (X - data_min) / (data_max - data_min + epsilon)

X = X.numpy()
X = X.astype(np.float32)

# test train the the data
print('Splitting data')
X_train = X
y_train = y

input_file = 'evaluation-dataset.csv'
print('Reading evaluation dataset')
df = pd.read_csv(input_file)

df[' Label'] = df[' Label'].astype(str)
y=df[' Label']

le = LabelEncoder()
y_encoded = le.fit_transform(y)  # y is your string labels

print(le.classes_)  # Just to confirm the mapping, e.g., ['benign' 'malicious']

y = to_categorical(y_encoded)

df = df.drop(' Label', axis=1)
df = df.drop('Flow ID', axis=1)
df = df.drop(' Source IP', axis=1)
df = df.drop(' Destination IP', axis=1)
df = df.drop([" Source Port", " Destination Port", " Protocol"], axis=1)

X=df.values[:,1:56]
FEATURES = df.columns
FEATURES = FEATURES[1:56]

X = (X - data_min) / (data_max - data_min + epsilon)

X_test = X
y_test = y

# 4. Define the Neural Network Model using Keras Sequential API

print(X_train.shape)

model = tf.keras.Sequential([
    tf.keras.layers.InputLayer(input_shape=(X_train.shape[1],)),
    tf.keras.layers.Dense(units=10, activation='relu'),
    tf.keras.layers.Dense(units=5, activation='relu'),
    tf.keras.layers.Dense(units=2, activation='relu')
])
# 5. Compile the Model
model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=0.003), # adjust learning rate here
              loss='binary_crossentropy',
              metrics=['accuracy', tf.keras.metrics.Precision(), tf.keras.metrics.Recall(), tf.keras.metrics.F1Score()])

# 6. Train the Model
history = model.fit(X_train, y_train, epochs=5, batch_size=32, validation_data=(X_test, y_test))

model.summary()
model.save('nn_model.keras')

# 7. Evaluate the Model on the Test Set
loss, accuracy, precision, recall, f1score = model.evaluate(X_test, y_test, verbose=0)
print(f"Test Loss: {loss:.4f}")
print(f"Test Accuracy: {accuracy:.4f}")
print(f"Test precision: {precision:.4f}")
print(f"Test recall: {recall:.4f}")
print(f1score)