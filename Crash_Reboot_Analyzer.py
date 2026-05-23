# analysis/Crash_Reboot_Analyzer.py

import re
from dataclasses import dataclass

# ---------------------------------------------------------
# EVENT DEFINITIONS (STRICT MATCHING — ONLY IN Dump_Debug_Logs)
# ---------------------------------------------------------

EVENTS = [
    {"event": "RF_ERROR_WAN_stopped",                  "type": "NETWORK", "id": 3001},
    {"event": "RF_ERROR_IPV6PingFailed",               "type": "NETWORK", "id": 3002},
    {"event": "RF_ERROR_IPV4PingFailed",               "type": "NETWORK", "id": 3003},
    {"event": "SYS_ERROR_PSMCrash_reboot",             "type": "RDKB",    "id": 2001},
    {"event": "SYS_ERROR_Dibbler_DAD_failed",          "type": "NETWORK", "id": 3004},
    {"event": "SYS_ERROR_CCSPBus_error190",            "type": "RDKB",    "id": 2002},
    {"event": "SYS_ERROR_CCSPBus_error191",            "type": "RDKB",    "id": 2004},
    {"event": "SYS_ERROR_LoadAbove5",                  "type": "SYSTEM",  "id": 4001},
    {"event": "SYS_ERROR_TMPFS_ABOVE85",               "type": "SYSTEM",  "id": 4002},
    {"event": "RF_ERROR_IPV4IPV6PingFailed",           "type": "NETWORK", "id": 3005},
    {"event": "SYS_ERROR_iptable_corruption",          "type": "SYSTEM",  "id": 4003},
    {"event": "SYS_ERROR_syseventdCrashed",            "type": "RDKB",    "id": 2005},
    {"event": "SYS_ERROR_Error_fetching_devicemode",   "type": "RDKB",    "id": 2006},
    {"event": "SYS_ERROR_brlan0_not_created",          "type": "NETWORK", "id": 3006},
    {"event": "WIFI_ERROR_WifiDmCliError",             "type": "WIFI",    "id": 1001},
    {"event": "SYS_ERROR_DmCli_Bridge_mode_error",     "type": "RDKB",    "id": 2007},
    {"event": "WIFI_ERROR_DMCLI_crash_5G_Status",      "type": "WIFI",    "id": 1002},
    {"event": "WIFI_ERROR_DMCLI_crash_2G_Status",      "type": "WIFI",    "id": 1003},
    {"event": "SYS_ERROR_DHCPV4Client_notrunnig",      "type": "NETWORK", "id": 3007},
    {"event": "SYS_ERROR_DHCPV6Client_notrunnig",      "type": "NETWORK", "id": 3008},
    {"event": "SYS_ERROR_DibblerServer_emptyconf",     "type": "NETWORK", "id": 3009},
    {"event": "SYS_ERROR_CM_Not_Registered",           "type": "RDKB",    "id": 2008},
    {"event": "SYS_ERROR_TR69_Not_Registered",         "type": "RDKB",    "id": 2009},
    {"event": "SYS_ERROR_PSM_Not_Registered",          "type": "RDKB",    "id": 2010},
    {"event": "SYS_ERROR_UsedCPU_15MIN_Above90",       "type": "SYSTEM",  "id": 4004},
    {"event": "SYS_ERROR_UsedCPU_HOURLY_Above90",      "type": "SYSTEM",  "id": 4005},
    {"event": "SYS_ERROR_UsedCPU_DEVICE_BOOT_Above90", "type": "SYSTEM",  "id": 4006},
    {"event": "SYS_ERROR_LOW_FREE_MEMORY",             "type": "SYSTEM",  "id": 4007},
    {"event": "SYS_ERROR_CPU100",                      "type": "SYSTEM",  "id": 4008},
    {"event": "RF_ERROR_erouter0_ipv4_loss",           "type": "NETWORK", "id": 3010},
    {"event": "RF_ERROR_erouter0_ipv6_loss",           "type": "NETWORK", "id": 3011},
    {"event": "EVT_WIFI_RESTART_2G_DRIVER_split",      "type": "WIFI",    "id": 1004},
    {"event": "EVT_BBHM_FILE_UNAVAILABLE_split",       "type": "RDKB",    "id": 2011},
    {"event": "EVT_SYSCFG_FILE_UNAVAILABLE_split",     "type": "RDKB",    "id": 2012},
    {"event": "SYS_INFO_FILE_SIZE_LIMIT_EXCEEDED",     "type": "SYSTEM",  "id": 4009},
    {"event": "WIFI_INFO_5G_DISABLED",                 "type": "WIFI",    "id": 1005},
    {"event": "WIFI_INFO_5GPrivateSSID_OFF",           "type": "WIFI",    "id": 1006},
    {"event": "WIFI_INFO_2G_DISABLED",                 "type": "WIFI",    "id": 1007},
    {"event": "WIFI_INFO_2GPrivateSSID_OFF",           "type": "WIFI",    "id": 1008},
]

# ---------------------------------------------------------
# COMPONENT HINTS
# ---------------------------------------------------------

COMPONENT_HINTS = {
    "WIFI": [r"ath11k", r"wlan\d", r"wifi\d", r"hostapd"],
    "DOCSIS": [r"CM", r"Cable Modem", r"ds\d+", r"us\d+"],
    "PON": [r"OMCI", r"PLOAM", r"XGSPON"],
    "SYSTEM": [r"systemd", r"init", r"kernel:"],
}

# ---------------------------------------------------------
# DATA CLASSES
# ---------------------------------------------------------

@dataclass
class Event:
    index: int
    timestamp: str | None
    event_name: str
    event_type: str
    event_id: int
    component: str | None
    line: str

@dataclass
class Episode:
    event: Event
    context_before: list[str]
    context_after: list[str]
    involved_components: list[str]

# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------

def extract_timestamp(line):
    m = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line)
    return m.group(0) if m else None

def detect_component(line):
    for comp, pats in COMPONENT_HINTS.items():
        if any(re.search(p, line, re.IGNORECASE) for p in pats):
            return comp
    return None

def extract_context(lines, idx, before=80, after=30):
    start = max(0, idx - before)
    end = min(len(lines), idx + after)
    return lines[start:end]

def collect_components(lines):
    comps = set()
    for ln in lines:
        c = detect_component(ln)
        if c:
            comps.add(c)
    return list(comps)

# ---------------------------------------------------------
# EVENT DETECTION (ONLY IN Dump_Debug_Logs)
# ---------------------------------------------------------

def detect_events(lines, filename):
    events = []

    if "Dump_Debug_Logs" not in filename:
        return events

    for i, line in enumerate(lines):
        for ev in EVENTS:
            if ev["event"].lower() in line.lower():
                events.append(Event(
                    index=i,
                    timestamp=extract_timestamp(line),
                    event_name=ev["event"],
                    event_type=ev["type"],
                    event_id=ev["id"],
                    component=detect_component(line),
                    line=line
                ))
    return events

# ---------------------------------------------------------
# BUILD EPISODES
# ---------------------------------------------------------

def build_episodes(lines, events):
    episodes = []
    for ev in events:
        ctx = extract_context(lines, ev.index)
        episodes.append(Episode(
            event=ev,
            context_before=ctx[:80],
            context_after=ctx[80:],
            involved_components=collect_components(ctx)
        ))
    return episodes

# ---------------------------------------------------------
# MAIN ENTRY POINT
# ---------------------------------------------------------

def analyze_crash_and_reboot(text, filename="", anomalies=None):
    """
    Returns:
        episodes → list of Episode objects
        anomaly_summary → dict with critical/high anomalies
    """
    lines = text.splitlines()
    events = detect_events(lines, filename)
    episodes = build_episodes(lines, events)

    # Summaries
    critical = []
    high = []

    if anomalies:
        for a in anomalies:
            sev = a.get("severity", "").lower()
            if sev == "critical":
                critical.append(a)
            elif sev == "high":
                high.append(a)

    anomaly_summary = {
        "critical": critical,
        "high": high
    }

    return episodes, anomaly_summary
