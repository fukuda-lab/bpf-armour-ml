# Training
This directory contains necessary files for training the anomaly detection algorithms (Decision Tree and Neural Network).

## Pre-requisites
* Python Environment
* C
* gcc
* sklearn
* Tensorflow
* Dataset in the form of CICFlowMeter format (pcap file, labeled csv)

## Data Pre-Processing
Before training, the dataset needs to undergo pre-processing to extract features and separation between training and evaluation dataset.

* Run extract_features.c in the following format
```bash
./extract_features [input_dataset_pcap_file].pcap >> [extracted_target].csv
```

* Run csv-to-train-data.py to label and separate the dataset.
```bash
Python3 csv-to-train-data.py [extracted_target].csv [dataset_labeled].csv
```
* The training and evaluation dataset will be generated as train-dataset.csv and evaluation-dataset.csv, respectively.


## Decision Tree Training
* Run ml_train.py to train a decision tree with sklearn.
```bash
Python3 ml_train.py
```
* The trained tree can be viewed as tree.pdf


## Neural Network Training
* Run nn_train.py to train a neural network with tensorflow.
