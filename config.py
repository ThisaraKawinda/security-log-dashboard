# config.py
# Central configuration for the Security Log Dashboard

# Event IDs we care about
EVENT_IDS = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4634: "Logoff",
    4647: "User Initiated Logoff",
    4672: "Special Privileges Assigned",
    4720: "User Account Created",
    4726: "User Account Deleted",
    4728: "Member Added to Global Security Group",
    4732: "Member Added to Local Security Group",
    4740: "Account Locked Out",
    4756: "Member Added to Universal Security Group",
    4688: "Process Created",
    4719: "Audit Policy Changed",
}

# Logon Type mappings
LOGON_TYPES = {
    2:  "Interactive (Local)",
    3:  "Network",
    4:  "Batch",
    5:  "Service",
    7:  "Unlock",
    8:  "NetworkCleartext",
    9:  "NewCredentials",
    10: "RemoteInteractive (RDP)",
    11: "CachedInteractive",
}

# Sub Status codes for failed logons (4625)
SUBSTATUS_CODES = {
    "0xc000006a": "Wrong password (user exists)",
    "0xc0000064": "Username does not exist",
    "0xc000006f": "Outside allowed logon hours",
    "0xc0000070": "Workstation restriction",
    "0xc0000072": "Account disabled",
    "0xc000015b": "Logon type not granted",
    "0xc0000234": "Account locked out",
    "0xc0000193": "Account expired",
}

# Detection thresholds
BRUTE_FORCE_THRESHOLD   = 5
BRUTE_FORCE_WINDOW_SECS = 300
UNUSUAL_HOUR_START      = 22
UNUSUAL_HOUR_END        = 6
SPRAY_ACCOUNT_THRESHOLD = 3

# Suspicious process patterns
SUSPICIOUS_CMDLINE_PATTERNS = [
    "-enc",
    "-encodedcommand",
    "bypass",
    "iex",
    "invoke-expression",
    "downloadstring",
    "webclient",
    "hidden",
    "net user",
    "whoami",
    "mimikatz",
]

SUSPICIOUS_PROCESSES = [
    "mimikatz.exe",
    "procdump.exe",
    "psexec.exe",
    "wce.exe",
    "fgdump.exe",
]

# Log collection settings
LOG_SOURCE     = "Security"
MAX_EVENTS     = 10000
LOOKBACK_HOURS = 24

# Storage
DB_PATH        = "data/security_logs.db"
EXPORT_CSV_PATH = "data/sample_logs/events_export.csv"
