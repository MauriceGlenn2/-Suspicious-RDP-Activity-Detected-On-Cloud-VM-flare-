# -Suspicious-RDP-Activity-Detected-On-Cloud-VM-flare-

## RDP Compromise Incident

**Report ID:** INC-2025-XXXX

**Analyst:** Maurice

**Date:** 4/15/2026

**Incident Date:** 14-September-2025

### **Key Indicators of Compromise (IOCs):**

- **Attack Source IP:** 159.26.106.84
- **Compromised Account:** slflare
- **Malicious File:** msupdate.exe
- **Persistence Mechanism:** "TaskName":"\\MicrosoftUpdateSync"
- **C2 Server:** ________________
- **Exfiltration Destination:** ________________


**Query 1 - Initial Access Detection:**
Remote device sanc-main (IP: 159.26.106.84) gained initial unauthorized access on September 16, 2025 and maintained persistent access through September 28, 2025. After the user changed their password, the attacker conducted a password spray attack which locked the account. The account was subsequently unlocked — likely by an insider or compromised admin — restoring attacker access within approximately 9 minutes. This sequence indicates a multi-phase, potentially assisted intrusion.
<br><br><br>
<img width="1430" height="958" alt="image" src="https://github.com/user-attachments/assets/9d4e7002-0d0f-4ce6-8ef4-3694ef1ac26a" />
<img width="941" height="857" alt="image" src="https://github.com/user-attachments/assets/5ec6b75c-5e69-4aac-b812-16450757ae3f" />
<br><br><br>
After gaining access to the device, the attacker ran a suspicious file called msupdate.exe on 9/16/2025 at 7:38 PM. This file was disguised to look like a legitimate Microsoft update process but was actually malicious. It was used to run a script called update_check.ps1 stored in a public folder, with security controls bypassed to allow it to execute.
Following this, the attacker set up a persistent service called MSUpdateService to maintain their access, then ran a series of commands to gather information about the system including user accounts, network configuration, and running processes.
<img width="1567" height="990" alt="image" src="https://github.com/user-attachments/assets/85d8b253-f61a-4c27-9cc7-7ba872b999d6" />
<br><br><br>
Query 3 - Persistence Detection:
On September 16, 2025, at 7:39:45 PM UTC, a scheduled task named MicrosoftUpdateSync was created on the device slflarewinsysmo under the account slflare. This task was configured to trigger on system boot and execute a hidden PowerShell command using the following arguments:
-ExecutionPolicy Bypass -WindowStyle Hidden -File C:\ProgramData\Microsoft\Windows\Update\mscloudsync.ps1
This technique allowed the attacker to establish persistence on the compromised machine, ensuring their malicious PowerShell script would automatically run every time the system restarted, without requiring any further user interaction. The task was deliberately named to blend in with legitimate Windows update processes, making it less likely to raise suspicion during a casual review.
<img width="1993" height="1011" alt="image" src="https://github.com/user-attachments/assets/779fa469-59a2-4d13-80d5-6656aaeae563" />




