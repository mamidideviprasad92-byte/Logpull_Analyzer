import pdfkit
from typing import Dict
import pandas as pd


def _safe_get(d: dict, key: str, default="N/A"):
    """Safely get a key from a dict without KeyError."""
    return d.get(key, default)


def _render_issues_table(anomalies_df: pd.DataFrame) -> str:
    if anomalies_df is None or anomalies_df.empty:
        return "<p>No anomalies detected.</p>"

    df = anomalies_df.copy().head(200)
    return df.to_html(index=False, escape=False)


def generate_html_report(summary: Dict, anomalies_df: pd.DataFrame) -> str:
    """
    Build a safe HTML report from summary + anomalies.
    Handles missing keys gracefully.
    """
    total_lines = summary.get("total_lines", 0)
    total_files = summary.get("total_files", 0)
    error_lines = summary.get("error_lines", 0)
    issues_count = summary.get("issues_count", 0)

    top_components = summary.get("top_components", [])
    top_errors = summary.get("top_error_messages", [])

    # Safe component rows
    comp_rows = "".join(
        f"<tr><td>{_safe_get(c, 'component')}</td><td>{_safe_get(c, 'count')}</td></tr>"
        for c in top_components
    )

    # Safe error rows
    err_rows = "".join(
        f"<tr><td>{_safe_get(e, 'message')}</td><td>{_safe_get(e, 'count')}</td></tr>"
        for e in top_errors
    )

    issues_table_html = _render_issues_table(anomalies_df)

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Log Pull Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ccc; padding: 6px 8px; font-size: 12px; }}
        th {{ background-color: #f2f2f2; }}
        .section {{ margin-bottom: 30px; }}
    </style>
</head>
<body>
    <h1>Log Pull Analysis Report</h1>


    <div class="section">
        <h2>Summary</h2>
        <ul>
            <li>Total log lines: {total_lines}</li>
            <li>Total files: {total_files}</li>
            <li>Error lines: {error_lines}</li>
            <li>Detected issues: {issues_count}</li>
        </ul>
    </div>

    <div class="section">
        <h2>Top Components</h2>
        <table>
            <tr><th>Component</th><th>Count</th></tr>
            {comp_rows}
        </table>
    </div>

    <div class="section">
        <h2>Top Error Messages</h2>
        <table>
            <tr><th>Message</th><th>Count</th></tr>
            {err_rows}
        </table>
    </div>

    <div class="section">
        <h2>Detected Anomalies (Sample)</h2>
        {issues_table_html}
    </div>

</body>
</html>
"""
    return html


def convert_html_to_pdf(html: str) -> bytes:
    """Convert HTML string to PDF bytes using pdfkit."""
    return pdfkit.from_string(html, False)