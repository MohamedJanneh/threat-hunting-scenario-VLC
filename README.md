

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/MohamedJanneh/threat-hunting-scenario-VLC/blob/main/threat-hunting-scenario-VLC%20-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- VLC Media Player

##  Scenario

Management received an alert suggesting unauthorized software might have been installed on user devices. Upon further investigation, traces of VLC Media Player installation and execution were found on the system named mohamed900. VLC, while not malicious by default, was not an approved application for enterprise use and its presence requires further investigation to ensure compliance.

### High-Level TOR-Related IoC Discovery Plan

- Check DeviceFileEvents for any vlc(.exe) related file creation or modification.
- Check DeviceProcessEvents for signs of installation or execution of VLC-related binaries.
- Check DeviceNetworkEvents for any VLC-based outbound network communication.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for file creation and modification events where the file name contained "vlc". Results showed the installer vlc-3.0.21-win64.exe was downloaded and shortcut files such as VLC media player.lnk were created in C:\ProgramData and C:\Users\Public\Desktop.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName has "vlc"
| where DeviceName == "mohamed900"
| order by Timestamp desc
```
<img width="1212" alt="1  related to vlc" src="https://github.com/user-attachments/assets/edf52358-bc4b-49da-9687-218d255d960d" />


---

### 2. Searched the `DeviceProcessEvents` Table

Checked for process creation related to VLC. Events showed execution of vlc.exe, vlc-cache-gen.exe, and the installer vlc-3.0.21-win64.exe.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where FileName has "vlc"
| where DeviceName == "mohamed900"
| order by Timestamp desc
```
<img width="1212" alt="2  all process" src="https://github.com/user-attachments/assets/12e308c8-f6e5-4f5c-8298-ed8595512a06" />


---

### 3. Searched the `DeviceNetworkEvents` Table 

Checked for any network activity related to VLC. The device mohamed900 connected to update.videolan.org and other domains over port 80, initiated by VLC-related processes.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName has "vlc"
| where DeviceName == "mohamed900"
| order by Timestamp desc
```

<img width="1212" alt="3  connection" src="https://github.com/user-attachments/assets/72cae919-ef5c-423a-ab78-6e185e67ba8b" />

---

### 4. Viewed Command Line Activity

Used extended query to review full command lines associated with VLC executions. The user account mo was responsible for launching the installer and VLC processes.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where FileName has "vlc"
| where DeviceName == "mohamed900"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="4 user info" src="https://github.com/user-attachments/assets/fd72cf5c-5522-4e53-82e0-5568776a1c7f" />

---

### 5. Verified Installer Activity

The installer vlc-3.0.21-win64.exe was renamed, showing direct interaction with the file system by the user or process.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName == "vlc-3.0.21-win64.exe"
| where DeviceName == "mohamed900"
| order by Timestamp desc
```
<img width="1212" alt="5  show logs installer" src="https://github.com/user-attachments/assets/4ae8f48c-292c-4932-8eff-1013fd4f0619" />


## Chronological Event Timeline 

## 🔎 Chronological Event Timeline

### 1. File Download – VLC Installer

- **Timestamp:** `2025-05-12T03:38:00Z`  
- **Event:** The user `"mo"` downloaded a file named `vlc-3.0.21-win64.exe` to the Downloads folder.  
- **Action:** File renamed after download.  
- **File Path:** `C:\Users\Public\Downloads\vlc-3.0.21-win64.exe`

---

### 2. Process Execution – VLC Installer

- **Timestamp:** `2025-05-12T03:39:00Z`  
- **Event:** The user `"mo"` executed the installer `vlc-3.0.21-win64.exe`, initiating the installation of VLC Media Player.  
- **Action:** Process creation detected.  
- **Command:** `vlc-3.0.21-win64.exe`  
- **File Path:** `C:\Users\Public\Downloads\vlc-3.0.21-win64.exe`

---

### 3. Process Execution – VLC Launch

- **Timestamp:** `2025-05-12T03:40:00Z`  
- **Event:** The VLC executable `vlc.exe` was launched by user `"mo"` multiple times after installation.  
- **Action:** Multiple process creations detected.  
- **File Path:** `C:\Program Files\VideoLAN\VLC\vlc.exe`

---

### 4. Network Connections – VLC Application

- **Timestamp:** `2025-05-12T03:40:00Z`  
- **Event:** VLC made several outbound connections on port `80`, likely for update checks or metadata retrieval.  
- **Action:** `ConnectionSuccess` events logged.  
- **Remote IPs & URLs:**
  - `142.251.16.207` → `http://commondatastorage.googleapis.com`
  - `213.36.253.119` → `http://update.videolan.org`
- **Initiating Process:** `vlc.exe`

---

✅ Summary
The user "mo" on device "mohamed900" downloaded and installed VLC Media Player (vlc-3.0.21-win64.exe). Shortly after installation, the application vlc.exe was launched multiple times and established successful outbound HTTP connections to official VLC update and storage domains. These actions confirm the installation and network activity of the VLC application, consistent with legitimate media player usage.
