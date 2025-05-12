# Threat Event (Unauthorized VLC Usage)
**Unauthorized VLC Media Player Installation and Use**

## Steps the "Bad Actor" took to Create Logs and IoCs:
1. Downloaded the VLC installer: https://www.videolan.org/vlc/
2. Saved the installer in `C:\Users\Public\temp`
3. Installed VLC: `vlc-3.0.21-win64.exe`
4. Launched VLC media player multiple times (`vlc.exe`)
5. VLC connected to several external update and metadata URLs, including:
   - `update.videolan.org`
   - `commondatastorage.googleapis.com`
6. Executed helper processes like `vlc-cache-gen.exe`
7. Created shortcuts and internal program files in `C:\Program Files\VideoLAN\VLC`

---

## Tables Used to Detect IoCs:
| **Parameter**         | **Description**                                                                                     |
|-----------------------|-----------------------------------------------------------------------------------------------------|
| **DeviceFileEvents**  | Detects downloads, creations, renames, and file interactions including `.exe`, `.lnk`, and other VLC-related files |
| **DeviceProcessEvents** | Tracks execution of the VLC installer and running VLC processes via command lines                 |
| **DeviceNetworkEvents** | Captures external connections made by VLC to update or metadata services                           |

---

## Related Queries (KQL):
```kql
// Find VLC installer dropped or renamed
DeviceFileEvents
| where FileName == "vlc-3.0.21-win64.exe"
| where DeviceName == "mohamed900"
| order by Timestamp desc

// Find any VLC-related file actions (install, shortcuts, etc.)
DeviceFileEvents
| where FileName has "vlc"
| where DeviceName == "mohamed900"
| order by Timestamp desc

// Track execution of VLC installer or player
DeviceProcessEvents
| where FileName has "vlc"
| where DeviceName == "mohamed900"
| order by Timestamp desc

// Get user and command line for VLC processes
DeviceProcessEvents
| where FileName has "vlc"
| where DeviceName == "mohamed900"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, ProcessCommandLine
| order by Timestamp desc

// Detect VLC network activity
DeviceNetworkEvents
| where InitiatingProcessFileName has "vlc"
| where DeviceName == "mohamed900"
| order by Timestamp desc

## Created By:
- **Author Name**: Mohamed Janneh  
- **Author Contact**: mohamedjanneh04@gmail.com  
- **LinkedIn**: https://www.linkedin.com/in/mojan638/  
- **Date**: May 12, 2025

## Validated By:
- **Reviewer Name**:  
- **Reviewer Contact**:  
- **Validation Date**:  

---

## Additional Notes:
- Logs collected from Defender for Endpoint (DeviceName: `mohamed900`)
- Screenshots labeled and organized for file, process, network, and user events

---

