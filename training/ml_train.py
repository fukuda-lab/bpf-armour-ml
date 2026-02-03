import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from sklearn.datasets import make_classification
from sklearn.metrics import classification_report, ConfusionMatrixDisplay, RocCurveDisplay, PrecisionRecallDisplay
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, plot_tree
from IPython.display import display

def output_trees(clfs, X_train, y_train):
    i = 0
    for clf in clfs:
        plt.figure(figsize=(25,5))
        plot_tree(clf, filled=True, feature_names=FEATURES, class_names=CLASS_NAMES, fontsize=5)
        plt.savefig('tree' + str(i) + '.pdf')
        plt.show()
        i = i + 1

def output_graphs(clf, X_test, y_test):

    i = 0
    for clf in clfs:
        y_pred_proba = clf.predict_proba(X_test)
        y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))

    fig, axes = plt.subplots(nrows=2, ncols=2, figsize=(12, 8), constrained_layout=True)
    fig.subplots_adjust(wspace=0.5, hspace=0.5)

    ConfusionMatrixDisplay.from_predictions(y_test, y_pred)

    # Feature Importance
    print(clf.feature_importances_)
    importances = pd.DataFrame({'Importance':clf.feature_importances_}, index=FEATURES)
    importances.sort_values('Importance', ascending=False).head(10).sort_values('Importance', ascending=True).plot.barh(ax=axes[0, 1], grid=True)

    feature_importances_df_sorted = importances.sort_values(by='Importance', ascending=False)
    print("\nFeature Importances (Sorted Pandas DataFrame):")
    print(feature_importances_df_sorted)

    # ROC
    RocCurveDisplay.from_predictions(y_test, y_pred_proba[:,1], pos_label='BENIGN', ax=axes[1, 0])
    axes[1, 0].set_title('ROC(Receiver Operating Characteristic) Curve')

    PrecisionRecallDisplay.from_predictions(y_test, y_pred_proba[:,1], pos_label='BENIGN', ax=axes[1, 1])

    plt.savefig('output_graphs' + str(i) + '.png')
    i = i + 1

input_file = 'train-dataset.csv'

print('Reading input file')
df = pd.read_csv(input_file)

CLASS_NAMES = df[' Label'].unique()

CLASS_NAMES = [str(name) for name in CLASS_NAMES]

y=df.values[:,df.columns.get_loc(' Label')]
y = y.astype(str)


df = df.drop(columns=["Flow ID"])
df = df.drop(columns=[" Source IP"]) 
df = df.drop(columns=[" Source Port"]) 
df = df.drop(columns=[" Destination IP"])
df = df.drop(columns=[" Destination Port"])
df = df.drop(columns=[" Protocol"])

df = df.drop(' Label', axis=1)

X=df.values[:,1:56]
FEATURES = df.columns
FEATURES = FEATURES[1:56]
print(FEATURES)

# test train the the data
X_train, y_train = X, y

## Creating testing dataset

input_file = 'evalation-dataset.csv'

print('Reading testing file')
df = pd.read_csv(input_file)

CLASS_NAMES = df[' Label'].unique()

# print(CLASS_NAMES)
CLASS_NAMES = [str(name) for name in CLASS_NAMES]

y_test=df.values[:,df.columns.get_loc(' Label')]
y_test = y_test.astype(str)

df = df.drop(columns=["Flow ID"])
df = df.drop(columns=[" Source IP"])
df = df.drop(columns=[" Source Port"]) 
df = df.drop(columns=[" Destination IP"])
df = df.drop(columns=[" Destination Port"])
df = df.drop(columns=[" Protocol"]) 

# df = df[[' Packet Length Variance', ' Fwd Packet Length Std', ' Bwd Packet Length Std', ' Bwd IAT Std', ' Fwd IAT Std', ' Flow IAT Std', ' Packet Length Std', ' Label']]

# df = df.drop(columns=[" Fwd Packet Length Mean", " Fwd Packet Length Std", " Bwd Packet Length Mean", 
#                       " Bwd Packet Length Std", "Flow Bytes/s", " Flow Packets/s", " Flow IAT Mean", 
#                       " Flow IAT Std", " Fwd IAT Mean", " Fwd IAT Std", "Bwd IAT Total", " Bwd IAT Mean", 
#                       " Bwd IAT Std", " Packet Length Mean", " Packet Length Std", " Packet Length Variance", 
#                       " Down/Up Ratio", " Average Packet Size"])

df = df.drop(' Label', axis=1)
X_test=df.values[:,1:56]


# Passing to the Decision Tree Classifier, with entropy criterion

clf = DecisionTreeClassifier(max_depth=5,random_state=100)

# Fitting the data  to the classifier
print('Start fitting')
clf.fit(X_train, y_train)
print("Fitting done")

clfs = []
clfs.append(clf)

train_scores = [clf.score(X_train, y_train) for clf in clfs[:-1]]
test_scores = [clf.score(X_test, y_test) for clf in clfs[:-1]]

output_graphs(clf, X_test, y_test)
output_trees(clfs, X_train, y_train)