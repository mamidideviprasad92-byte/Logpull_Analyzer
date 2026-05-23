import pandas as pd


def search_logs(df_logs: pd.DataFrame, query: str) -> pd.DataFrame:
    """
    Search for a keyword across all logs.
    Returns rows containing:
      - timestamp
      - file
      - raw log line
    """
    if not query or df_logs.empty:
        return pd.DataFrame()

    df = df_logs.copy()
    df = df[df["raw"].str.contains(query, case=False, na=False)]

    # Clean timestamp formatting
    if "timestamp" in df.columns:
        df["timestamp"] = df["timestamp"].astype(str).replace(["NaT", "None", ""], None)

    cols = ["timestamp", "file", "raw"]
    existing = [c for c in cols if c in df.columns]
    return df[existing]