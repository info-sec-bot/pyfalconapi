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
