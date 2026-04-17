# -Suspicious-RDP-Activity-Detected-On-Cloud-VM-flare-

# RDP Compromise Incident

**Report ID:** INC-2025-XXXX

**Analyst:** Maurice Glenn

**Date:** 4/15/2026

**Incident Date:** 14-September-2025

### **Key Indicators of Compromise (IOCs):**

- **Attack Source IP:** 159.26.106.84
- **Compromised Account:** slflare
- **Malicious File:** msupdate.exe
- **Persistence Mechanism:** "TaskName":"\\MicrosoftUpdateSync"
- **C2 Server:** 185.92.220.87
- **Exfiltration Destination:** 185.92.220.87:8081


# Query 1 - Initial Access Detection T1059.003, T1204.002:
Remote device sanc-main (IP: 159.26.106.84) gained initial unauthorized access on September 16, 2025 and maintained persistent access through September 28, 2025. After the user changed their password, the attacker conducted a password spray attack which locked the account. The account was subsequently unlocked — likely by an insider or compromised admin — restoring attacker access within approximately 9 minutes. This sequence indicates a multi-phase, potentially assisted intrusion.
<br><br><br>
<img width="1430" height="958" alt="image" src="https://github.com/user-attachments/assets/9d4e7002-0d0f-4ce6-8ef4-3694ef1ac26a" />
<img width="941" height="857" alt="image" src="https://github.com/user-attachments/assets/5ec6b75c-5e69-4aac-b812-16450757ae3f" />
<br><br><br>
After gaining access to the device, the attacker ran a suspicious file called msupdate.exe on 9/16/2025 at 7:38 PM. This file was disguised to look like a legitimate Microsoft update process but was actually malicious. It was used to run a script called update_check.ps1 stored in a public folder, with security controls bypassed to allow it to execute.
Following this, the attacker set up a persistent service called MSUpdateService to maintain their access, then ran a series of commands to gather information about the system including user accounts, network configuration, and running processes.
<img width="1567" height="990" alt="image" src="https://github.com/user-attachments/assets/85d8b253-f61a-4c27-9cc7-7ba872b999d6" />
<br><br><br>

# Query 3 - Persistence Detection T1053.005:
On September 16, 2025, at 7:39:45 PM UTC, a scheduled task named MicrosoftUpdateSync was created on the device slflarewinsysmo under the account slflare. This task was configured to trigger on system boot and execute a hidden PowerShell command using the following arguments:
-ExecutionPolicy Bypass -WindowStyle Hidden -File C:\ProgramData\Microsoft\Windows\Update\mscloudsync.ps1
This technique allowed the attacker to establish persistence on the compromised machine, ensuring their malicious PowerShell script would automatically run every time the system restarted, without requiring any further user interaction. The task was deliberately named to blend in with legitimate Windows update processes, making it less likely to raise suspicion during a casual review.
<img width="1993" height="1011" alt="image" src="https://github.com/user-attachments/assets/779fa469-59a2-4d13-80d5-6656aaeae563" />

<br><br><br>
# Query 4 - Modify Windows Defender T1562.001:
On September 27, 2025, two suspicious executables, payload.exe and winsetup.exe, were observed running on the host slflarewinsysmo under the account slflare. Both processes launched PowerShell to tamper with Windows Defender in a sequence of escalating actions. First, payload.exe disabled real-time monitoring and added C:\Windows\Temp as a Defender exclusion path. Shortly after, winsetup.exe continued the attack by disabling additional Defender protections and adding an exclusion for the entire C:\ drive, effectively rendering Windows Defender blind to any malicious files or activity on the system.

<img width="1665" height="940" alt="image" src="https://github.com/user-attachments/assets/b0e24178-dee6-47c4-be1f-5f2e8914b385" />
<img width="1633" height="278" alt="image" src="https://github.com/user-attachments/assets/a5bfb5bd-c33c-496e-93cd-eac6cd97bb2f" />
<br><br><br>

# Query 5 - Archive Collected Data: Local Archiving T1560.001:
On September 16, 2025 at 7:41 PM UTC, the user account "slflare" on device "slflarewinsysmo" created the first observed archive file named backup_sync.zip, staged in the user's local Temp folder. This appears to be the starting point of the attacker's data collection and archiving phase.
<img width="1489" height="709" alt="image" src="https://github.com/user-attachments/assets/10d9288f-9aab-43d3-8a7c-eefb9b990f5a" />
<br><br><br>

# Query 6 - C2 Connection Destination T1071.001, T1105, T1048.003:
On September 16, 2025, an attacker using the compromised account SLFlare exfiltrated a file called backup_sync.zip from the device slflarewinsysmo to an external server at 185.92.220.87 on port 8081. They used both curl and PowerShell to upload the file, likely to make sure at least one method succeeded.
Eleven days later on September 27, the attacker came back and exfiltrated a second file called export.7z, this time sending it to an internal host at 10.0.105.104 on port 8083. The same dual method approach was used again with curl and PowerShell.

<img width="1997" height="716" alt="image" src="https://github.com/user-attachments/assets/296a17d8-f59c-4478-ae65-ca91c9688323" />








