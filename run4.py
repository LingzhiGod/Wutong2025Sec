import pandas as pd
import os

# This function is not allowed to be modified
def read_data(input_file_path):
    if not os.path.exists(input_file_path):
        raise FileNotFoundError(f"Error: File '{input_file_path}' does not exist")
    if not input_file_path.endswith('.csv'):
        raise ValueError("Error: Please provide a CSV file")

    df = pd.read_csv(input_file_path)
    return df
# This function is not allowed to be modified
def output_data(result_df, output_file_path):
    anomaly_fields = ['login_account', 'operation_time', 'anomaly_type']
    missing_anomaly_fields = [field for field in anomaly_fields if field not in result_df.columns]

    if missing_anomaly_fields:
        raise ValueError(f"Missing anomaly detection fields: {', '.join(missing_anomaly_fields)}")

    output_dir = os.path.dirname(output_file_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    output_df = result_df[anomaly_fields]
    output_df.to_csv(output_file_path, index=False)
    return True
########################################################
import numpy as np
import re

THRESH_5MIN = 8
THRESH_24H = 80
THRESH_5MIN_NONSENS = 8
THRESH_1H_PRIV = 10
WORK_START = 8
WORK_END = 19

SENSITIVE_PATTERNS = [
    re.compile(r'@'),
    re.compile(r'1[3-9]\d\*{3,}\d{2,4}'),
    re.compile(r'[A-Za-z0-9._%+-]{2,}\*+[A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
]

def is_sensitive_content(text):
    if not isinstance(text, str):
        return False
    if '****' in text:
        return True
    for regex in SENSITIVE_PATTERNS:
        if regex.search(text):
            return True
    return False

#解析时间信息
def resolve_timedata(df):
    parsed_time = pd.to_datetime(df["operation_time"], errors="coerce", utc=True)
    df["operation_ts"] = parsed_time.astype("int64") // 1_000_000_000
    df["operation_hour"] = parsed_time.dt.hour

def detect_group(group):
    acct = group.iloc[0]['login_account']

    ts = group["operation_ts"].values
    hours = group["operation_hour"].values
    urls = group["page_url"].fillna("").astype(str).values
    priv = group["privilege_level"].fillna(2).astype(int).values
    content = group["operation_content"].fillna("").astype(str).values
    orig_times = group["operation_time"].values

    n = len(group)
    is_sensitive_page = np.array([u.lstrip().startswith(("/products")) for u in urls])
    is_non_sensitive = ~is_sensitive_page

    abnormal_idx = {1: set(), 2: set(), 3: set(), 4: set(), 5: set()}

    #Type4:敏感内容
    for i, c in enumerate(content):
        if is_sensitive_content(c):
            abnormal_idx[4].add(i)

    for i in range(n):
        t = ts[i]

        #Type1 and Type3
        j = np.searchsorted(ts, t + 300, side="right")

        if j - i > THRESH_5MIN:
            abnormal_idx[1].update(range(i, j))

        # non_sens_idx = [k for k in range(i, j) if is_non_sensitive[k]]
        non_sens_urls = [urls[k] for k in range(i, j) if is_non_sensitive[k]]
        if len(set(non_sens_urls)) > THRESH_5MIN_NONSENS:
            abnormal_idx[3].update(k for k in range(i, j) if is_non_sensitive[k])

        #Type2
        j = np.searchsorted(ts, t + 86400, side="right")
        if j - i >= THRESH_24H:
            abnormal_idx[2].update(range(i, j))

        if priv[i] == 1 and (hours[i] < WORK_START or hours[i] >= WORK_END):
            j = np.searchsorted(ts, t + 3600, side="right")
            sens_idx = [k for k in range(i, j) if is_sensitive_page[k]]
            if len(sens_idx) >= THRESH_1H_PRIV:
                abnormal_idx[5].update(sens_idx)

    records = []
    for tp, idxs in abnormal_idx.items():
        for k in idxs:
            records.append((acct, orig_times[k], tp))

    return records

def data_process(df):
    resolve_timedata(df)
    print("Found " + str(len(df)) + " logs")
    df = df.sort_values(["login_account", "operation_time"])
    groups = df.groupby("login_account", sort=False)

    global_result = []
    for _,group in groups:
        global_result.extend(detect_group(group.reset_index(drop=True)))

    if len(global_result) == 0:
        out = pd.DataFrame(columns=["login_account", "operation_time", "anomaly_type"])
    else:
        out = pd.DataFrame(global_result, columns=["login_account", "operation_time", "anomaly_type"])
    out = out.drop_duplicates().sort_values(["login_account", "operation_time", "anomaly_type"])
    print("Detected " + str(len(out)) + " warning!")
    return out
import time
def process_competition_data(input_file_path, output_file_path):
    try:
        df = read_data(input_file_path)

#Write your code in the area below.The final output result must be assigned to the variable 'result_df'
#################################################################################
        start_time = time.time()
        result_df = data_process(df)
        end_time = time.time()
        print("Cost" + str(end_time - start_time) + "s")
        global_stat = result_df["anomaly_type"].value_counts().sort_index()
        print(global_stat)
#################################################################################

        output_data(result_df, output_file_path)
        return result_df

    except Exception as e:
        return f"Error during processing: {str(e)}"

if __name__ == "__main__":
    input_csv_path = "user_behavior_data.csv"
    output_csv_path = "test.csv"
    data = process_competition_data(input_csv_path, output_csv_path)