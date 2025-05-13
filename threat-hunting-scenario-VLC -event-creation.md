# Threat Event (Unauthorized VLC Installation and Use)
**Unauthorized VLC Media Player Installation and Use**

---

## Steps the "Bad Actor" took to Create Logs and IoCs:
1. Downloaded the VLC media player installer from an external source.
2. Renamed the installer: `vlc-3.0.21-win64.exe`.
3. Executed the VLC installer manually from the Downloads folder.
4. Installed the VLC application into `C:\Program Files\VideoLAN\VLC\`.
5. Launched `vlc.exe` multiple times.
6. VLC attempted outbound network connections to media-related and update domains:
   - `update.videolan.org`
   - `commondatastorage.googleapis.com`
7. VLC created multiple shortcut `.lnk` files in public folders.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the VLC installer and shortcut files being created or renamed. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect VLC installer execution and VLC application launch. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect VLC network connections to external update and media sources (port 80). |

---

## Related Queries:
```kql
// Detect any VLC-related file creation or renaming
DeviceFileEvents
| where FileName has "vlc"
| where DeviceName == "mohamed900"
| order by Timestamp desc

// Detect execution of VLC installer and VLC processes
DeviceProcessEvents
| where FileName has "vlc"
| where DeviceName == "mohamed900"
| order by Timestamp desc

// Detect outbound network activity by VLC to update or media sources
DeviceNetworkEvents
| where InitiatingProcessFileName has "vlc"
| where DeviceName == "mohamed900"
| order by Timestamp desc

// Include command-line context and user info for validation
DeviceProcessEvents
| where FileName has "vlc"
| where DeviceName == "mohamed900"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, ProcessCommandLine
| order by Timestamp desc

// Verify installer file specifically
DeviceFileEvents
| where FileName == "vlc-3.0.21-win64.exe"
| where DeviceName == "mohamed900"
| order by Timestamp desc
```

---

## Created By:
- **Author Name**: Mohamed Janneh
- **Author Contact**: mohamedjanneh04@gmail.com
- **Date**: May 12, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **Screenshots and log evidence available in repo directory**

---

## Revision History:
| **Version** | **Changes**      | **Date**       | **Modified By**     |
|-------------|------------------|----------------|----------------------|
| 1.0         | Initial draft     | `May 12, 2025` | `Mohamed Janneh`     
