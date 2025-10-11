import pandas as pd
import os
import sys


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


##########################################################################################

# ================== 规则参数 ==================
THRESH_5MIN = 8
THRESH_24H = 80
THRESH_5MIN_NONSENS = 8
THRESH_1H_PRIV = 10
WORK_START = 8
WORK_END = 19

import numpy as np
from datetime import datetime, timezone
import re

SENSITIVE_PATTERNS = [
    re.compile(r'@'),
    re.compile(r'1[3-9]\d\*{3,}\d{2,4}'),
    re.compile(r'[A-Za-z0-9._%+-]{2,}\*{1,}[A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
]


def is_sensitive_content(text):
    if not isinstance(text, str):
        return False
    if '*' in text:
        return True
    for regex in SENSITIVE_PATTERNS:
        if regex.search(text):
            return True
    return False


def fmt_time(tt: datetime):
    dt = pd.to_datetime(tt).tz_localize(None)  # 去掉时区，保证格式
    return f"{dt.year:04d}/{dt.month:02d}/{dt.day:02d} {dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"


def singleGroupDetect(group):
    result = []
    # Data Prepare
    acct = group.iloc[0]['login_account']

    times = group["operation_time"].dt.tz_localize(None)
    ts = times.astype("int64") // 1_000_000_000
    urls = group["page_url"].fillna("").astype(str).values
    priv = group["privilege_level"].fillna(2).astype(int).values
    content = group["operation_content"].fillna("").astype(str).values

    n = len(group)
    is_sensitive_page = np.array([u.startswith("/products") for u in urls])
    is_non_sensitive = ~is_sensitive_page

    # Mark
    abnormal_idx = {1: set(), 2: set(), 3: set(), 4: set(), 5: set()}

    # Type 4 Detection
    for i, c in enumerate(content):
        if is_sensitive_content(c):
            abnormal_idx[4].add(i)

    # 滑动窗口方式
    for i in range(n):
        t = ts[i]

        # Type1 5min 8+
        j = np.searchsorted(ts, t + 300, side="right")
        if j - i > THRESH_5MIN:
            abnormal_idx[1].update(range(i + THRESH_5MIN, j))

        # Type2: 24h >=80
        j = np.searchsorted(ts, t + 86400, side="right")
        if j - i >= THRESH_24H:
            abnormal_idx[2].update(range(i + THRESH_24H, j))

        # Type3: 5min non sensitive 8+
        j = np.searchsorted(ts, t + 300, side="right")
        if np.sum(is_non_sensitive[i:j]) > THRESH_5MIN_NONSENS:
            count = 0
            for k in range(i, j):
                if is_non_sensitive[k]:
                    count += 1
                    if count > THRESH_5MIN_NONSENS:
                        abnormal_idx[3].add(k)

        # Type5：priv,non work, sensitive page 1h 10+
        if priv[i] == 1:
            hour = datetime.fromtimestamp(int(ts[i]), tz=timezone.utc).hour
            if hour < WORK_START or hour >= WORK_END:
                j = np.searchsorted(ts, t + 3600, side="right")
                cnt = np.sum(is_sensitive_page[i:j])
                if cnt >= THRESH_1H_PRIV:
                    count = 0
                    for k in range(i, j):
                        if is_sensitive_page[k]:
                            count += 1
                            if count > THRESH_1H_PRIV:
                                abnormal_idx[5].add(k)

    records = []
    for tp, idxs in abnormal_idx.items():
        for k in idxs:
            records.append((acct, fmt_time(times.iloc[k]), tp))

    return records


def entry(df):
    # Pre Data process
    df["operation_time"] = pd.to_datetime(df["operation_time"])
    df = df.sort_values(["login_account", "operation_time"])
    groups = df.groupby("login_account", sort=False)
    print("Found " + str(len(df)) + " logs")

    # Group Detection
    globalResult = []
    for name, group in groups:
        globalResult.extend(singleGroupDetect(group.reset_index(drop=True)))

    # Post Data Process
    if len(globalResult) == 0:
        out = pd.DataFrame(columns=["login_account", "operation_time", "anomaly_type"])
    else:
        out = pd.DataFrame(globalResult, columns=["login_account", "operation_time", "anomaly_type"])
    out["operation_time"] = out["operation_time"].apply(fmt_time)
    out = out.drop_duplicates().sort_values(["login_account", "operation_time", "anomaly_type"])
    print("Detected " + str(len(out)) + " warning!")
    return out


def process_competition_data(input_file_path, output_file_path):
    # try:
    df = read_data(input_file_path)

    # Write your code in the area below.The final output result must be assigned to the variable 'result_df'
    #################################################################################
    result_df = entry(df)
    # debug
    account_stats = result_df.groupby(["login_account", "anomaly_type"]).size().unstack(fill_value=0)
    account_stats.to_csv("account_trigger_stats.csv", encoding="utf-8-sig")

    global_stats = result_df["anomaly_type"].value_counts().sort_index()
    global_stats.to_csv("global_trigger_stats.csv", header=["count"], encoding="utf-8-sig")

    detections = result_df

    account_total = df.groupby("login_account").size()
    account_abnormal = detections.groupby("login_account").size()
    account_ratio = (account_abnormal / account_total).fillna(0).sort_values(ascending=False)
    account_ratio.to_csv("account_ratio.csv", header=["abnormal_ratio"], encoding="utf-8-sig")

    # === 2. 时段分布统计 ===
    detections["hour"] = pd.to_datetime(detections["operation_time"], format="%Y/%m/%d %H:%M:%S").dt.hour
    time_distribution = detections.groupby(["anomaly_type", "hour"]).size().unstack(fill_value=0)
    time_distribution.to_csv("time_distribution.csv", encoding="utf-8-sig")
    #################################################################################

    output_data(result_df, output_file_path)
    return result_df

    # except Exception as e:
    # print(e)
    return f"Error during processing: {str(e)}"


if __name__ == "__main__":
    input_csv_path = "user_behavior_data.csv"
    output_csv_path = "test.csv"
    data = process_competition_data(input_csv_path, output_csv_path)