import pandas as pd
import sys

# ファイル名を指定
file1_path = sys.arv[1]
file2_path = sys.arv[2]

try:
    df1 = pd.read_csv(file1_path, index_col=None)
    df2 = pd.read_csv(file2_path, index_col=0)
    df2 = df2.drop_duplicates(subset='Flow ID', keep='first')
    merged_df = pd.merge(df1, df2[['Flow ID', ' Label']], on='Flow ID', how='left')

    merged_df = merged_df.drop(columns=["Unnamed: 61"])
    merged_df = merged_df.replace('Web Attack – Brute Force', 'Attack')
    merged_df = merged_df.replace('Web Attack – XSS', 'Attack')
    merged_df = merged_df.replace('Web Attack – Sql Injection', 'Attack')
    merged_df = merged_df.dropna()
except FileNotFoundError:
    print("Unable to find csv file. Please check input variables.")
except KeyError as e:
        print(f"Unable to find row labelled as '{e}' inside the csv file. Please check input file.")
except Exception as e:
    print(f"Unexpected error: {e}")

try:
        df_train = merged_df[merged_df.index % 3 != 0]
        df_evaluation = merged_df[merged_df.index % 3 == 0]
        # print(f"元の行数: {len(df)}, 除外後の行数: {len(df_filtered)}")

        df_train.to_csv('train-dataset.csv', index=False)
        df_evaluation.to_csv('evaluation-dataset.csv', index=False)

except Exception as e:
    print(f"Unexpected error: {e}")