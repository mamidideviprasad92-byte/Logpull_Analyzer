import re
import pandas as pd
from datetime import datetime

BOOTUP_REGEX = re.compile(
    r"^(?P<time>\d{2}:\d{2}:\d{2})\s+\[(?P<component>[^\]]+)\]\s+(?P<message>.*)$"
)

FULL_TS_REGEX = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+(?P<level>[A-Z]+)\s+(?P<component>\S+)\s+(?P<message>.*)$"
)

SYSLOG_REGEX = re.compile(
    r"^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<component>\S+)\s+(?P<message>.*)$"
)

BRACKET_COMPONENT_REGEX = re.compile(
    r"^\[(?P<component>[^\]]+)\]\s+(?P<message>.*)$"
)

GENERIC_SYSLOG = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<component>\S+):?\s+(?P<message>.*)$"
)

def parse_bootup_line(line):
    match = BOOTUP_REGEX.match(line)
    if not match:
        return None
    try:
        timestamp = datetime.strptime(match.group("time"), "%H:%M:%S")
    except Exception:
        timestamp = None
    return {
        "timestamp": timestamp,
        "level": "BOOT",
        "component": match.group("component"),
        "message": match.group("message"),
        "raw": line,
    }

def parse_full_timestamp(line):
    match = FULL_TS_REGEX.match(line)
    if not match:
        return None
    try:
        timestamp = datetime.fromisoformat(match.group("ts"))
    except Exception:
        timestamp = None
    return {
        "timestamp": timestamp,
        "level": match.group("level"),
        "component": match.group("component"),
        "message": match.group("message"),
        "raw": line,
    }

def parse_syslog(line):
    match = SYSLOG_REGEX.match(line)
    if not match:
        return None
    try:
        timestamp = datetime.strptime(match.group("ts"), "%b %d %H:%M:%S")
    except Exception:
        timestamp = None
    return {
        "timestamp": timestamp,
        "level": "INFO",
        "component": match.group("component"),
        "message": match.group("message"),
        "raw": line,
    }

def parse_bracket_component(line):
    match = BRACKET_COMPONENT_REGEX.match(line)
    if not match:
        return None
    return {
        "timestamp": None,
        "level": "INFO",
        "component": match.group("component"),
        "message": match.group("message"),
        "raw": line,
    }

def parse_generic_syslog(line):
    match = GENERIC_SYSLOG.match(line)
    if not match:
        return None
    try:
        ts_str = f"{match.group('month')} {match.group('day')} {match.group('time')}"
        timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S")
    except:
        timestamp = None
    return {
        "timestamp": timestamp,
        "level": "INFO",
        "component": match.group("component"),
        "message": match.group("message"),
        "raw": line,
    }

def extract_tables_from_file(file_path):
    tables = {}
    current_table = None
    header = None
    rows = []

    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")

            if line.strip().endswith("table") or line.strip().endswith("Table"):
                if current_table and header and rows:
                    df = pd.DataFrame(rows, columns=header)
                    tables[current_table] = df
                current_table = line.strip()
                header = None
                rows = []
                continue

            if current_table and header is None and line.strip() and not set(line.strip()) == {"-"}:
                header = re.split(r"\s{2,}", line.strip())
                continue

            if current_table and header and set(line.strip()) == {"-"}:
                continue

            if current_table and header and line.strip():
                parts = re.split(r"\s{2,}", line.strip())
                if len(parts) < len(header):
                    parts += [""] * (len(header) - len(parts))
                elif len(parts) > len(header):
                    parts = parts[:len(header) - 1] + [" ".join(parts[len(header) - 1:])]
                rows.append(parts)
                continue

            if current_table and not line.strip():
                if header and rows:
                    df = pd.DataFrame(rows, columns=header)
                    tables[current_table] = df
                current_table = None
                header = None
                rows = []

    if current_table and header and rows:
        df = pd.DataFrame(rows, columns=header)
        tables[current_table] = df

    return tables

def parse_logs_to_df(log_files):
    rows = []
    all_tables = {}

    for file_path in log_files:
        file_tables = extract_tables_from_file(file_path)
        all_tables.update(file_tables)

        with open(file_path, "r", errors="ignore") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line.strip():
                    continue

                for parser in (
                    parse_bootup_line,
                    parse_full_timestamp,
                    parse_syslog,
                    parse_generic_syslog,
                    parse_bracket_component,
                ):
                    parsed = parser(line)
                    if parsed:
                        parsed["file"] = file_path
                        rows.append(parsed)
                        break
                else:
                    rows.append({
                        "timestamp": None,
                        "level": None,
                        "component": None,
                        "message": None,
                        "raw": line,
                        "file": file_path,
                    })

    df = pd.DataFrame(rows)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    return df, all_tables