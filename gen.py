import pandas as pd
from datetime import datetime, timedelta
import random

def generate_debug_data(
    n_type1=12,    # Type1: 5分钟内 >8 次访问
    n_type2=85,    # Type2: 24小时 ≥80 次访问
    n_type3=10,     # Type3: 5分钟内 >8 次非敏感页面访问
    n_type4=5,     # Type4: 含敏感内容（手机号/邮箱）
    n_type5=14,    # Type5: 特权账号非工作时间 ≥10 次敏感访问
    n_noise=50     # 垃圾 / 干扰数据
):
    records = []
    base_time = datetime(2025, 9, 14, 9, 0, 0)

    # --- Type1 ---
    for i in range(n_type1):
        records.append(("acct_type1", 2, "/products/test", base_time + timedelta(seconds=i*20), "Normal access"))

    # --- Type2 ---
    for i in range(n_type2):
        records.append(("acct_type2", 2, "/products/test", base_time + timedelta(minutes=i*10), "Normal access"))

    # --- Type3 ---
    for i in range(n_type3):
        records.append(("acct_type3", 2, "/marketing/page", base_time + timedelta(seconds=i*30), "Normal access"))

    # --- Type4 ---
    sensitive_examples = [
        "Phone: 138****1234",
        "Email: test****@example.com",
        "Secure data operation - user liu****88@test.com",
        "Encrypted data transfer - 150****9371"
    ]
    for i in range(n_type4):
        records.append(("acct_type4", 2, "/confidential/hr", base_time + timedelta(seconds=i*40), random.choice(sensitive_examples)))

    # --- Type5 ---
    night_time = datetime(2025, 9, 14, 22, 0, 0)
    for i in range(n_type5):
        records.append(("acct_type5", 1, "/confidential/data", night_time + timedelta(minutes=i*3), "Privileged access"))

    # --- 垃圾 / 误导数据 ---
    noise_urls = ["/random/page", "/ads/banner", "/confidential/fake", "/products/demo"]
    noise_contents = [
        # "*** just stars ***",   # 误导：带星号但无敏感信息
        "Test user access",     # 普通访问
        "Login success",        # 日志类信息
        "Error code: 500",      # 系统错误信息
        "Visit homepage"        # 非异常行为
    ]
    for i in range(n_noise):
        records.append((
            f"acct_noise{i%5}",
            random.choice([1,2]),
            random.choice(noise_urls),
            base_time + timedelta(minutes=random.randint(0, 600)),
            random.choice(noise_contents)
        ))

    # 转为 DataFrame
    df = pd.DataFrame(records, columns=["login_account","privilege_level","page_url","operation_time","operation_content"])
    df["operation_time"] = df["operation_time"].dt.strftime("%Y/%m/%d %H:%M:%S")

    return df

# 生成示例
debug_df = generate_debug_data(n_type1=12, n_type2=90, n_type3=10, n_type4=6, n_type5=15, n_noise=100)
debug_df.to_csv("debug_data.csv", index=False, encoding="utf-8-sig")

