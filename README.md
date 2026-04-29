<p align="left">
    <img src="img/Pyfalconapi.png" alt="pyfalconapi">
</p>

# pyfalconapi

- [Overview](#overview)
  - [falconapi-GetBrowserHistory](falconapi-GetBrowserHistory.py)
  - [falconapi-DelBrowserHistory](falconapi-DelBrowserHistory.py)
## Overview
#### Contains a suite of tools built to access the Crowdstrike Falcon API in Python utilizing the falconpy library. 
#### https://falconpy.io/Home.html

## Authentication
#### 1. `falconapi-GetBrowserHistory.py` uses the `falcon_auth.py` module to use API credentials stored in a keyvault see the comments in the code for further guidance on vault set up. You will need to be logged in as a user with required privileges to access.
## Actions
#### 1. `falconapi-GetBrowserHistory.py` uses the `BrowsingHistoryView.exe` executable provided by NirSoft
####     https://www.nirsoft.net/utils/browsing_history_view.html
#### 2. The executable must be uploaded to the Falcon console prior to execution. 
#### Upload the Executable: Upload your binary (e.g., .exe, .ps1) to the CrowdStrike Falcon RTR Library 
#### (under Configuration -> File library).
## Usage
#### `python3 falconapi-GetBrowserHistory.py`
```
Please enter hostname: UserHostPC
2026-04-29 11:59:49,335 [INFO] Querying devices for hostname pattern: 'UserHostPC'
2026-04-29 11:59:50,034 [INFO] Fetching device details for AID: abc123
2026-04-29 11:59:50,493 [INFO] Initiating RTR session for device: 456cba
2026-04-29 11:59:52,097 [INFO] RTR session established: 111-222-333-444-55555
2026-04-29 11:59:52,582 [INFO] Putting BrowsingHistoryView.exe on host...
2026-04-29 11:59:53,081 [INFO] Running 'Pull Browser History' script on host...
2026-04-29 11:59:53,640 [INFO] Running ls command on host...
```
