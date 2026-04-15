# -Suspicious-RDP-Activity-Detected-On-Cloud-VM-flare-

## RDP Compromise Incident

**Report ID:** INC-2025-XXXX

**Analyst:** Maurice

**Date:** 4/15/2026

**Incident Date:** 14-September-2025

### **Key Indicators of Compromise (IOCs):**

- **Attack Source IP:** ________________
- **Compromised Account:** ________________
- **Malicious File:** ________________
- **Persistence Mechanism:** ________________
- **C2 Server:** ________________
- **Exfiltration Destination:** ________________

### **KQL Queries Used:** *(Document your investigation methodology)*

**Query 1 - Initial Access Detection:**

let StartTime = datetime(2025-09-14T00:00:00Z);
let EndTime = datetime(2025-09-30T23:59:59Z);

//Checks logon  events from 9/14 - 9/30 shows remote access with successful log on attempts from 159.26.106.84
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "flare"
| where AccountName == "slflare"
| project Timestamp, DeviceName, RemoteIP, AccountName, AccountDomain, ActionType, RemoteDeviceName, FailureReason
| order by Timestamp asc 


//basic information
DeviceLogonEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "flare"
| where AccountName contains "slflare"


| summarize 
    Failures = countif(ActionType == "LogonFailed"),
    Successes = countif(ActionType == "LogonSuccess")
    by AccountName
| order by Failures desc


// Check if sanc-main is a known device in your environment
DeviceInfo
| where Timestamp between (StartTime .. EndTime)
| where DeviceName == "sanc-mai"


