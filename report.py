import pandas as pd
from typing import Dict, List


def build_report(df: pd.DataFrame, issues: List[Dict]) -> Dict:
    """
    Build a simple summary report from logs and detected issues.
    """
    report = {
        "total_lines": int(len(df)),
        "total_files": int(df["file"].nunique()) if not df.empty and "file" in df.columns else 0,
        "error_lines": 0,
        "event_found_count": len(issues),
        "top_components": [],
        "top_error_messages": [],
    }

    if df.empty:
        return report

    # ---------------------------------------------------------
    # ERROR LINE COUNT
    # ---------------------------------------------------------
    if "level" in df.columns:
        level_series = df["level"].fillna("").astype(str).str.upper()
        error_mask = level_series.isin(["ERROR", "CRIT", "CRITICAL"])
        report["error_lines"] = int(error_mask.sum())

    # ---------------------------------------------------------
    # TOP COMPONENTS (CLEAN + SAFE)
    # ---------------------------------------------------------
    if "component" in df.columns:
        comp_counts = (
            df["component"]
            .fillna("")
            .value_counts()
            .head(5)
            .reset_index()
        )

        # Normalize column names safely
        # After reset_index(), columns are usually: ["index", "component"]
        # But we rename them to: ["component", "count"]
        comp_counts = comp_counts.rename(columns={
            comp_counts.columns[0]: "component",
            comp_counts.columns[1]: "count"
        })

        # Ensure only the required columns exist
        comp_counts = comp_counts.loc[:, ["component", "count"]]

        report["top_components"] = comp_counts.to_dict(orient="records")

    # ---------------------------------------------------------
    # TOP ERROR MESSAGES
    # ---------------------------------------------------------
    if "level" in df.columns and "message" in df.columns:
        level_series = df["level"].fillna("").astype(str).str.upper()
        err_df = df[level_series.isin(["ERROR", "CRIT", "CRITICAL"])]

        if not err_df.empty:
            msg_counts = (
                err_df["message"]
                .fillna("")
                .value_counts()
                .head(5)
                .reset_index()
                .rename(columns={
                    "index": "message",
                    "message": "count"
                })
            )
            report["top_error_messages"] = msg_counts.to_dict(orient="records")

    return report