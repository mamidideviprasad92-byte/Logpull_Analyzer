import re

MODEL_PATTERNS = [
    r"Model:\s*(.*)",
    r"Hardware Model:\s*(.*)",
    r"Product Model:\s*(.*)",
    r"Device\.DeviceInfo\.ModelName\s*=\s*(.*)",
    r"GW Model:\s*(.*)",
]

FW_PATTERNS = [
    r"Firmware Version:\s*(.*)",
    r"SW Version:\s*(.*)",
    r"Software Version:\s*(.*)",
    r"Device\.DeviceInfo\.SoftwareVersion\s*=\s*(.*)",
    r"FW:\s*(.*)",
    r"Image Build:\s*(.*)",
]

def extract_first_match(patterns, text):
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            value = m.group(1).strip()
            # Clean trailing junk
            value = value.split()[0] if len(value) > 40 else value
            return value
    return None

def extract_device_info(full_log_text):
    model = extract_first_match(MODEL_PATTERNS, full_log_text)
    firmware = extract_first_match(FW_PATTERNS, full_log_text)

    return {
        "model": model or "Unknown",
        "firmware": firmware or "Unknown"
    }