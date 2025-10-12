import pandas as pd
import numpy as np

# ========== 参数 ==========
THRESH_5MIN_NONSENS = 8

def type3_raw_check(df, output_path="type3_raw_check.csv"):
    results = []
    groups = df.groupby("login_account", sort=False)

    for acct, group in groups:
        group = group.sort_values("operation_ts").reset_index(drop=True)
        ts = group["operation_ts"].values
        urls = group["page_url"].fillna("").astype(str).values
        times = group["operation_time"].values

        is_sensitive = np.array([u.lstrip().startswith(("/products")) for u in urls])
        is_non_sensitive = ~is_sensitive

        n = len(group)
        for i in range(n):
            t = ts[i]
            j = np.searchsorted(ts, t + 300, side="right")

            # 取 5 分钟窗口内的非敏感访问
            non_sens_idx = [k for k in range(i, j) if is_non_sensitive[k]]

            if len(non_sens_idx) > THRESH_5MIN_NONSENS:
                results.append({
                    "login_account": acct,
                    "start_time": times[i],
                    "end_time": times[j-1] if j-1 < n else times[-1],
                    "total_non_sens": len(non_sens_idx),
                    "urls_in_order": "; ".join(urls[k] for k in non_sens_idx)
                })

    out = pd.DataFrame(results)
    out.to_csv(output_path, index=False, encoding="utf-8-sig")
    print(f"[INFO] 已导出 {len(out)} 条 Type3 检测窗口，保存至 {output_path}")
    return out


if __name__ == "__main__":
    # 读取原始数据
    df = pd.read_csv("user_behavior_data.csv")

    # 确保有 operation_ts (秒级时间戳)
    df["operation_time"] = pd.to_datetime(df["operation_time"], errors="coerce", utc=True)
    df["operation_ts"] = df["operation_time"].astype("int64") // 1_000_000_000

    type3_raw_check(df, "type3_raw_check.csv")
