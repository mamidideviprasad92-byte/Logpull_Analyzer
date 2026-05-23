import pandas as pd


def generate_ai_summary(df_logs: pd.DataFrame, df_issues: pd.DataFrame) -> str:
    """
    Lightweight heuristic summary (no external AI).
    Uses counts, severities, and categories to build a readable summary.
    """
    if df_logs.empty:
        return "No log lines were parsed from the uploaded files."

    total_lines = len(df_logs)
    total_files = df_logs["file"].nunique() if "file" in df_logs.columns else 0

    parts = []
    parts.append(f"Parsed approximately {total_lines} log lines across {total_files} file(s).")

    if not df_issues.empty:
        parts.append(f"Detected {len(df_issues)} anomaly events based on known gateway and DOCSIS patterns.")

        if "severity" in df_issues.columns:
            sev_counts = df_issues["severity"].value_counts().to_dict()
            sev_str = ", ".join(f"{k}: {v}" for k, v in sev_counts.items())
            parts.append(f"Severity distribution: {sev_str}.")

        if "category" in df_issues.columns:
            cat_counts = df_issues["category"].value_counts().head(5).to_dict()
            cat_str = ", ".join(f"{k}: {v}" for k, v in cat_counts.items())
            parts.append(f"Most impacted categories: {cat_str}.")
    else:
        parts.append("No anomalies were detected using the current keyword and classification rules.")

    return " ".join(parts)