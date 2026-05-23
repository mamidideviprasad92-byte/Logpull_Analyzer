import re
import streamlit as st
import pandas as pd
import os
import sys
import plotly.express as px
import warnings
warnings.filterwarnings("ignore", category=pd.errors.SettingWithCopyWarning)

from st_aggrid import AgGrid, GridOptionsBuilder

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))

from analysis.extractor import extract_archive, list_log_files
from analysis.parser import parse_logs_to_df
from analysis.rules import detect_anomalies
from analysis.report import build_report
from analysis.report_exporter import generate_html_report, convert_html_to_pdf
from analysis.search_engine import search_logs
from analysis.ai_engine import ask_question
from analysis.Crash_Reboot_Analyzer import analyze_crash_and_reboot

# ---------------------------------------------------------
# Page Config
# ---------------------------------------------------------
st.set_page_config(
    page_title="Log Pull Analyzer",
    layout="wide",
    page_icon="📡"
)

st.markdown("## 📡 Cable Modem Gateway Log Pull Analyzer")

# ---------------------------------------------------------
# Sidebar: Single Log Upload
# ---------------------------------------------------------
st.sidebar.header("🖥️ Single Log Mode")

uploaded_file = st.sidebar.file_uploader(
    "Upload Log Pull",
    type=["zip", "7z", "tgz", "tar.gz", "tar"],
    key="single_upload"
)

if not uploaded_file:
    st.info("Upload a log pull to continue.")
    st.stop()

# ---------------------------------------------------------
# Core Processing
# ---------------------------------------------------------
file_bytes = uploaded_file.read()

with st.spinner("Extracting archive..."):
    extract_dir = extract_archive(file_bytes, uploaded_file.name)

log_files = list_log_files(extract_dir)

with st.spinner("Parsing logs and tables..."):
    df_logs, tables = parse_logs_to_df(log_files)

with st.spinner("Running anomaly detection..."):
    issues = detect_anomalies(df_logs)

df_issues = pd.DataFrame(issues) if issues else pd.DataFrame()

# ---------------------------------------------------------
# Build Summary Report ONCE (so all tabs can use it)
# ---------------------------------------------------------
try:
    report = build_report(df_logs, issues)
except Exception as e:
    report = {"error": f"build_report() failed: {e}"}


# Build full log text (for AI context)
full_log_text = ""
for lf in log_files:
    try:
        with open(lf, "r", errors="ignore") as f:
            full_log_text += f.read() + "\n"
    except:
        pass

st.session_state["full_log_text"] = full_log_text
# ---------------------------------------------------------
# Navigation (REPLACES st.tabs)
# ---------------------------------------------------------
tab_names = [
    "🚨 Anomalies",
    "📊 Summary",
    "📤 Report",
    "🔍 Search",
    "📊 Tables",
    "💥 Crash/Reboot",
    "📁 Text Files"
]

if "active_tab" not in st.session_state:
    st.session_state.active_tab = tab_names[0]

st.session_state.active_tab = st.radio(
    "Navigation",
    tab_names,
    index=tab_names.index(st.session_state.active_tab),
    horizontal=True
)

# ---------------------------------------------------------
# Helper: AgGrid Wrapper
# ---------------------------------------------------------
import uuid

def render_table_aggrid(df: pd.DataFrame, height: int = 400, key: str = None):
    if df is None or df.empty:
        st.info("No data to display.")
        return

    if key is None:
        key = f"aggrid_{uuid.uuid4().hex}"

    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_default_column(
        resizable=True,
        sortable=True,
        filter=True,
        wrapText=True,
        autoHeight=True,
    )
    grid_options = gb.build()

    AgGrid(
        df,
        gridOptions=grid_options,
        height=height,
        theme="streamlit",
        fit_columns_on_grid_load=True,
        key=key,
    )

# ---------------------------------------------------------
# TAB: ANOMALIES
# ---------------------------------------------------------
if st.session_state.active_tab == "🚨 Anomalies":
    st.subheader("Detected Events & Anomalies")

    if df_issues.empty:
        st.success("No anomalies detected.")
    else:
        sev_filter = st.multiselect("Filter by severity", df_issues["severity"].unique())
        cat_filter = st.multiselect("Filter by category", df_issues["category"].unique())
        kw_search = st.text_input("Search in anomaly log lines")

        df_view = df_issues.copy()

        if sev_filter:
            df_view = df_view[df_view["severity"].isin(sev_filter)]
        if cat_filter:
            df_view = df_view[df_view["category"].isin(cat_filter)]
        if kw_search and "log_line" in df_view.columns:
            df_view = df_view[df_view["log_line"].astype(str).str.contains(kw_search, case=False, na=False)]

        render_table_aggrid(df_view, height=400)

# ---------------------------------------------------------
# TAB: SUMMARY
# ---------------------------------------------------------
if st.session_state.active_tab == "📊 Summary":
    st.subheader("Summary & Insights")

    try:
        report = build_report(df_logs, issues)
    except Exception as e:
        report = {"error": f"build_report() failed: {e}"}
        st.error(report["error"])

    st.markdown("### Raw Summary Object")
    st.json(report)

    if "level" in df_logs.columns:
        fig = px.bar(df_logs["level"].value_counts(), title="Log Level Distribution")
        st.plotly_chart(fig, use_container_width=True)

    if "timestamp" in df_logs.columns:
        df_time = df_logs.dropna(subset=["timestamp"]).copy()
        if not df_time.empty:
            df_time["minute"] = df_time["timestamp"].dt.floor("T")
            if "level" in df_time.columns:
                err_df = df_time[df_time["level"].astype(str).str.contains("ERROR|CRIT", case=False, na=False)]
                if not err_df.empty:
                    fig2 = px.line(err_df.groupby("minute").size(), title="Errors Over Time")
                    st.plotly_chart(fig2, use_container_width=True)

# ---------------------------------------------------------
# TAB: REPORT
# ---------------------------------------------------------
if st.session_state.active_tab == "📤 Report":
    st.subheader("Export Report")

    html_report = generate_html_report(summary=report, anomalies_df=df_issues)

    st.download_button(
        "📄 Download HTML Report",
        data=html_report,
        file_name="logpull_report.html",
        mime="text/html"
    )

    pdf_bytes = convert_html_to_pdf(html_report)

    st.download_button(
        "📘 Download PDF Report",
        data=pdf_bytes,
        file_name="logpull_report.pdf",
        mime="application/pdf"
    )

# ---------------------------------------------------------
# TAB: SEARCH
# ---------------------------------------------------------
if st.session_state.active_tab == "🔍 Search":
    st.subheader("Search Logs")

    file_options = ["All Files"] + [os.path.basename(f) for f in log_files]
    selected_file = st.selectbox("Select a file to search", file_options)

    search_term = st.text_input("Enter keyword to search")

    if search_term:
        if selected_file == "All Files":
            results = search_logs(df_logs, search_term)

            if results.empty:
                st.warning("No matching log entries found.")
            else:
                st.success(f"Found {len(results)} matching log entries across all files.")
                render_table_aggrid(results, height=400)

        else:
            full_path = None
            for lf in log_files:
                if os.path.basename(lf) == selected_file:
                    full_path = lf
                    break

            if not full_path:
                st.error("Selected file not found.")
            else:
                try:
                    with open(full_path, "r", errors="ignore") as f:
                        lines = f.readlines()
                except:
                    st.error("Unable to read the selected file.")
                    lines = []

                matched = []
                for line in lines:
                    if search_term.lower() in line.lower():
                        ts = None
                        m = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line)
                        if m:
                            ts = m.group(0)

                        matched.append({
                            "timestamp": ts,
                            "file": selected_file,
                            "log_line": line.strip()
                        })

                df_match = pd.DataFrame(matched)

                if df_match.empty:
                    st.warning(f"No matches found in {selected_file}.")
                else:
                    st.success(f"Found {len(df_match)} matches in {selected_file}.")
                    render_table_aggrid(df_match, height=400)

# ---------------------------------------------------------
# TAB: TABLES
# ---------------------------------------------------------
if st.session_state.active_tab == "📊 Tables":
    st.subheader("Extracted Tabular Data")
    if not tables:
        st.info("No tables found in this log pull.")
    else:
        table_names = list(tables.keys())
        selected = st.selectbox("Select a table", table_names)
        render_table_aggrid(tables[selected], height=400)
# ---------------------------------------------------------
# TAB: CRASH / REBOOT (Updated to include Critical/Major anomalies)
# ---------------------------------------------------------
if st.session_state.active_tab == "💥 Crash/Reboot":
    st.subheader("Crash & Reboot Analysis")

    # -----------------------------------------------------
    # 1. Show Critical & Major anomalies from ALL files
    # -----------------------------------------------------
    st.markdown("## 🔥 Critical & Major Events (All Files)")

    crit_major = df_issues[df_issues["severity"].isin(["Critical", "Major"])]

    if crit_major.empty:
        st.info("No Critical or Major anomalies found in this log pull.")
    else:
        for idx, row in crit_major.iterrows():
            st.markdown(f"### 🚨 {row['severity']} — {row['keyword']}")
            st.write(f"**File:** {row['file']}")
            st.write(f"**Component:** {row['component']}")
            st.write(f"**Timestamp:** {row.get('timestamp')}")

            if row.get("context"):
                st.markdown("#### Context (50 lines before & after)")
                st.code(row["context"], language="text")
            else:
                st.info("No context available for this event.")

            st.markdown("---")

    # -----------------------------------------------------
    # 2. Crash/Reboot events from Dump_Debug_Logs (existing logic)
    # -----------------------------------------------------
    st.markdown("## 💥 Crash / Reboot Events (Dump_Debug_Logs)")

    dump_file = None
    for lf in log_files:
        if "Dump_Debug_Logs" in lf:
            dump_file = lf
            break

    if not dump_file:
        st.info("No Dump_Debug_Logs file found in this log pull.")
    else:
        with open(dump_file, "r", errors="ignore") as f:
            dump_text = f.read()

        with st.spinner("Analyzing crash events and anomalies..."):
            episodes, anomaly_summary = analyze_crash_and_reboot(
                dump_text,
                filename=dump_file,
                anomalies=issues
            )

        # -----------------------------
        # Show Critical Anomalies
        # -----------------------------
        st.markdown("### 🔥 Critical Anomalies (Dump_Debug_Logs)")
        if anomaly_summary["critical"]:
            df_crit = pd.DataFrame(anomaly_summary["critical"])
            render_table_aggrid(df_crit, height=300)
        else:
            st.success("No critical anomalies detected in Dump_Debug_Logs.")

        # -----------------------------
        # Show High Anomalies
        # -----------------------------
        st.markdown("### ⚠️ High Anomalies (Dump_Debug_Logs)")
        if anomaly_summary["high"]:
            df_high = pd.DataFrame(anomaly_summary["high"])
            render_table_aggrid(df_high, height=300)
        else:
            st.success("No high anomalies detected in Dump_Debug_Logs.")

        # -----------------------------
        # Show Crash/Reboot Episodes
        # -----------------------------
        st.markdown("### 💥 Crash / Reboot Events")

        if not episodes:
            st.success("No crash/reboot events detected in Dump_Debug_Logs.")
        else:
            for idx, ep in enumerate(episodes, 1):
                st.markdown(f"### Event {idx}: {ep.event.event_name}")

                st.write(f"**Type:** {ep.event.event_type}")
                st.write(f"**Event ID:** {ep.event.event_id}")
                st.write(f"**Timestamp:** {ep.event.timestamp}")
                st.write(f"**Component:** {ep.event.component}")

                st.markdown("#### Context Before (20 lines)")
                st.code("\n".join(ep.context_before[-20:]))

                st.markdown("#### Context After (20 lines)")
                st.code("\n".join(ep.context_after[:20]))

                st.markdown("---")

# ---------------------------------------------------------
# TAB: TEXT FILES (Notepad++ style viewer with line numbers + search)
# ---------------------------------------------------------
if st.session_state.active_tab == "📁 Text Files":
    st.subheader("View Text / Log Files")

    # Build dropdown list of files
    file_options = [os.path.basename(f) for f in log_files]
    selected_file = st.selectbox("Select a file to view", file_options)

    # Search box inside the file
    search_in_file = st.text_input("Search inside file (optional)")

    if selected_file:
        # Find full path
        full_path = None
        for lf in log_files:
            if os.path.basename(lf) == selected_file:
                full_path = lf
                break

        if not full_path:
            st.error("Selected file not found.")
        else:
            try:
                with open(full_path, "r", errors="ignore") as f:
                    lines = f.readlines()
            except Exception as e:
                st.error(f"Unable to read file: {e}")
                lines = []

            # -----------------------------------------
            # Add line numbers
            # -----------------------------------------
            numbered_lines = []
            for idx, line in enumerate(lines, start=1):
                numbered_lines.append(f"{idx:5d} | {line.rstrip()}")

            # -----------------------------------------
            # Apply search filter if user typed something
            # -----------------------------------------
            if search_in_file:
                filtered = [
                    ln for ln in numbered_lines
                    if search_in_file.lower() in ln.lower()
                ]

                if not filtered:
                    st.warning("No matches found in this file.")
                else:
                    st.success(f"Found {len(filtered)} matching lines.")
                    st.code("\n".join(filtered), language="text")

            else:
                # Show full file with line numbers
                st.code("\n".join(numbered_lines), language="text")
