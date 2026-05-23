import pandas as pd
from typing import List, Dict
import re

# ---------------------------------------------------------
# 1. USER KEYWORDS (search in ALL files)
# ---------------------------------------------------------

USER_KEYWORDS = [
    "Listen normally on 3 erouter0",
    "NTP quick sync succeeded",
    "PA received parameterValueChangeSignal",
    "Value Changed event saved into PSM",
    "ACS Request has completed",
    "DNS servers configures successfully",
    "SYSEVENT_NTP_TIME_SYNC",
    "TRANSITION DUAL STACK ACTIVE",
    "Lan Status = started",
    "Wan Status = started",
    "setupIPv4",
    "setupIPv6",
    "IP configuration",
    "SYS_INFO_DNS_updated",
    "is Registered",
    "ph_state_wan_configured",
    "TELCOVOICEMANAGER_IPV6_WANUP",
    "Ploam.RegistrationState",
    "Veip.1.OperationalState",
    "Telemetry 2.0 Component Init Success",
    "Fetch complete for TR-181",
    "CurlStatus : 1",
    "Report Sent Successfully",
    "doHttpGet with url",
    "markers successfully added",
    "migrations are handled successfuly",
    "mesh enable set",
    "Connected to: redirector",
    "Connected to: manager",
    "dslite_start",
    "Received reboot_reason",
    "Call trace",
    "Tainted",
]

# ---------------------------------------------------------
# 2. CABLE MODEM KEYWORDS (search in ALL files)
# ---------------------------------------------------------

CABLE_MODEM_KEYWORDS = [
    "CM-STATUS",
    "T3 timeout",
    "T4 timeout",
    "Ranging Retry",
    "Lost MDD",
    "SYNC Timing Synchronization failure",
    "No Ranging Response received",
    "DHCP FAILED",
    "DHCP RENEW",
    "WAN LINK DOWN",
    "WAN LINK UP",
    "LAN LINK DOWN",
    "LAN LINK UP",
    "MIMO Event",
    "OFDM",
    "OFDMA",
    "US profile assignment",
    "DS profile assignment",
    "WiFi crash",
    "kernel panic",
    "reboot",
    "core dump",
    "fatal",
    "segfault",
]

# ---------------------------------------------------------
# 3. EVENT LIST (search ONLY in Dump_Debug_Logs)
# ---------------------------------------------------------

EVENTS = [
    {"event": "RF_ERROR_WAN_stopped", "type": "NETWORK", "id": 3001},
    {"event": "RF_ERROR_IPV6PingFailed", "type": "NETWORK", "id": 3002},
    {"event": "RF_ERROR_IPV4PingFailed", "type": "NETWORK", "id": 3003},
    {"event": "SYS_ERROR_PSMCrash_reboot", "type": "RDKB", "id": 2001},
    {"event": "SYS_ERROR_Dibbler_DAD_failed", "type": "NETWORK", "id": 3004},
    {"event": "SYS_ERROR_CCSPBus_error190", "type": "RDKB", "id": 2002},
    {"event": "SYS_ERROR_CCSPBus_error191", "type": "RDKB", "id": 2004},
    {"event": "SYS_ERROR_LoadAbove5", "type": "SYSTEM", "id": 4001},
    {"event": "SYS_ERROR_TMPFS_ABOVE85", "type": "SYSTEM", "id": 4002},
    {"event": "RF_ERROR_IPV4IPV6PingFailed", "type": "NETWORK", "id": 3005},
    {"event": "SYS_ERROR_iptable_corruption", "type": "SYSTEM", "id": 4003},
    {"event": "SYS_ERROR_syseventdCrashed", "type": "RDKB", "id": 2005},
    {"event": "SYS_ERROR_Error_fetching_devicemode", "type": "RDKB", "id": 2006},
    {"event": "SYS_ERROR_brlan0_not_created", "type": "NETWORK", "id": 3006},
    {"event": "WIFI_ERROR_WifiDmCliError", "type": "WIFI", "id": 1001},
    {"event": "SYS_ERROR_DmCli_Bridge_mode_error", "type": "RDKB", "id": 2007},
    {"event": "WIFI_ERROR_DMCLI_crash_5G_Status", "type": "WIFI", "id": 1002},
    {"event": "WIFI_ERROR_DMCLI_crash_2G_Status", "type": "WIFI", "id": 1003},
    {"event": "SYS_ERROR_DHCPV4Client_notrunnig", "type": "NETWORK", "id": 3007},
    {"event": "SYS_ERROR_DHCPV6Client_notrunnig", "type": "NETWORK", "id": 3008},
    {"event": "SYS_ERROR_DibblerServer_emptyconf", "type": "NETWORK", "id": 3009},
    {"event": "SYS_ERROR_CM_Not_Registered", "type": "RDKB", "id": 2008},
    {"event": "SYS_ERROR_TR69_Not_Registered", "type": "RDKB", "id": 2009},
    {"event": "SYS_ERROR_PSM_Not_Registered", "type": "RDKB", "id": 2010},
    {"event": "SYS_ERROR_UsedCPU_15MIN_Above90", "type": "SYSTEM", "id": 4004},
    {"event": "SYS_ERROR_UsedCPU_HOURLY_Above90", "type": "SYSTEM", "id": 4005},
    {"event": "SYS_ERROR_UsedCPU_DEVICE_BOOT_Above90", "type": "SYSTEM", "id": 4006},
    {"event": "SYS_ERROR_LOW_FREE_MEMORY", "type": "SYSTEM", "id": 4007},
    {"event": "SYS_ERROR_CPU100", "type": "SYSTEM", "id": 4008},
    {"event": "RF_ERROR_erouter0_ipv4_loss", "type": "NETWORK", "id": 3010},
    {"event": "RF_ERROR_erouter0_ipv6_loss", "type": "NETWORK", "id": 3011},
    {"event": "EVT_WIFI_RESTART_2G_DRIVER_split", "type": "WIFI", "id": 1004},
    {"event": "EVT_BBHM_FILE_UNAVAILABLE_split", "type": "RDKB", "id": 2011},
    {"event": "EVT_SYSCFG_FILE_UNAVAILABLE_split", "type": "RDKB", "id": 2012},
    {"event": "SYS_INFO_FILE_SIZE_LIMIT_EXCEEDED", "type": "SYSTEM", "id": 4009},
    {"event": "WIFI_INFO_5G_DISABLED", "type": "WIFI", "id": 1005},
    {"event": "WIFI_INFO_5GPrivateSSID_OFF", "type": "WIFI", "id": 1006},
    {"event": "WIFI_INFO_2G_DISABLED", "type": "WIFI", "id": 1007},
    {"event": "WIFI_INFO_2GPrivateSSID_OFF", "type": "WIFI", "id": 1008},
]

# ---------------------------------------------------------
# COMPONENT CLASSIFICATION
# ---------------------------------------------------------

def classify_component(text: str) -> str:
    t = text.lower()
    if any(x in t for x in ["t3 timeout", "t4 timeout", "cm-status", "mdd", "ranging", "docsis"]):
        return "DOCSIS"
    if any(x in t for x in ["dhcp", "wan", "lan", "ipv4", "ipv6"]):
        return "NETWORK"
    if any(x in t for x in ["wifi", "wlan", "radio"]):
        return "WIFI"
    if any(x in t for x in ["kernel", "segfault", "core dump", "fatal"]):
        return "SYSTEM"
    return "OTHER"

# ---------------------------------------------------------
# SEVERITY CLASSIFICATION
# ---------------------------------------------------------

def classify_severity(text: str) -> str:
    t = text.lower()

    # Critical
    if any(x in t for x in ["kernel panic", "segfault", "core dump", "fatal", "wifi crash"]):
        return "Critical"

    # Major
    if any(x in t for x in ["dhcp failed", "reboot", "t3 timeout", "t4 timeout"]):
        return "Major"

    # Low
    if any(x in t for x in ["wan link", "lan link"]):
        return "Low"

    return "Info"

# ---------------------------------------------------------
# CONTEXT EXTRACTION
# ---------------------------------------------------------

def extract_context(df: pd.DataFrame, index: int, before=50, after=50):
    start = max(0, index - before)
    end = min(len(df), index + after)
    return df.iloc[start:end]["raw"].tolist()

# ---------------------------------------------------------
# MAIN ANOMALY DETECTION
# ---------------------------------------------------------

def detect_anomalies(df: pd.DataFrame) -> List[Dict]:
    issues = []

    if df.empty or "raw" not in df.columns:
        return issues

    # -----------------------------------------
    # 1. USER KEYWORDS (search in ALL files)
    # -----------------------------------------
    for kw in USER_KEYWORDS:
        matches = df[df["raw"].str.contains(kw, case=False, na=False)]
        for idx, row in matches.iterrows():
            issues.append({
                "keyword": kw,
                "file": row["file"],
                "timestamp": row.get("timestamp"),
                "log_line": row["raw"],
                "component": "USER",
                "category": "USER",
                "severity": "Info",
                "context": None,
        })


    # -----------------------------------------
    # 2. CABLE MODEM KEYWORDS (search in ALL files)
    # -----------------------------------------
    for kw in CABLE_MODEM_KEYWORDS:
        matches = df[df["raw"].str.contains(kw, case=False, na=False)]
        for idx, row in matches.iterrows():
            component = classify_component(row["raw"])
            severity = classify_severity(row["raw"])

            context = None
            if severity in ["Critical", "Major"]:
                context = extract_context(df, idx)

            issues.append({
                "keyword": kw,
                "file": row["file"],
                "timestamp": row.get("timestamp"),
                "log_line": row["raw"],
                "component": component,
                "category": component,
                "severity": severity,
                "context": "\n".join(context) if context else None,
            })
 

    # -----------------------------------------
    # 3. EVENTS (search ONLY in Dump_Debug_Logs)
    # -----------------------------------------
    dump_df = df[df["file"].str.contains("Dump_Debug_Logs", case=False, na=False)]

    for ev in EVENTS:
        kw = ev["event"]
        matches = dump_df[dump_df["raw"].str.contains(kw, case=False, na=False)]
        for idx, row in matches.iterrows():
            issues.append({
                "keyword": kw,
                "event_name": kw,
                "event_type": ev["type"],
                "event_id": ev["id"],
                "file": row["file"],
                "timestamp": row.get("timestamp"),
                "log_line": row["raw"],
                "component": ev["type"],
                "category": ev["type"],
                "severity": "Critical",
                "context": "\n".join(extract_context(df, idx)),
            })


    return issues
