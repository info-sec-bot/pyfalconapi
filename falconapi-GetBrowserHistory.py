import os
import time
import sys
import re
import logging

# Requires Crowdstrike falcon and falconpy python package
from falcon_auth import get_falcon_credentials

creds = get_falcon_credentials()

print(creds["client_id"], creds["client_secret"],
creds["rclient_id"], creds["rclient_secret"])

from falconpy import RealTimeResponse, RealTimeResponseAdmin, Hosts

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# Do not hardcode API credentials!
RCLIENT_ID = os.environ['RCLIENTID']
RCLIENT_SECRET = os.environ['RCLIENT_SECRET']
CLIENT_ID = os.environ['CLIENT_ID']
CLIENT_SECRET = os.environ['CLIENT_SECRET']


def check_api_response(response, context="API call"):
    """
    Validates a FalconPy API response.
    Raises RuntimeError if the HTTP status code indicates failure,
    or if the response body contains errors.
    Returns the response on success.
    """
    status_code = response.get("status_code")
    body = response.get("body", {})
    errors = body.get("errors") or []

    if status_code is None:
        raise RuntimeError(f"{context}: Response missing status_code. Raw response: {response}")

    if status_code not in (200, 201):
        error_detail = "; ".join(
            f"[{e.get('code')}] {e.get('message', 'Unknown error')}" for e in errors
        ) or "No error detail provided."
        raise RuntimeError(f"{context} failed (HTTP {status_code}): {error_detail}")

    if errors:
        error_detail = "; ".join(
            f"[{e.get('code')}] {e.get('message', 'Unknown error')}" for e in errors
        )
        log.warning(f"{context} returned errors: {error_detail}")

    return response


def get_resources(response, context="API call", index=0):
    """
    Safely extracts response["body"]["resources"][index].
    Raises RuntimeError if resources are missing or empty.
    """
    resources = response.get("body", {}).get("resources")
    if not resources:
        raise RuntimeError(f"{context}: No resources returned in response.")
    if index >= len(resources):
        raise RuntimeError(f"{context}: Expected resource at index {index}, but only {len(resources)} returned.")
    return resources[index]


# ── Hosts client ─────────────────────────────────────────────────────────────
falcon = Hosts(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)

hostname = input("Please enter hostname: ").strip()
if not hostname:
    log.error("Hostname cannot be empty.")
    sys.exit(1)

# ── Resolve hostname → AID ────────────────────────────────────────────────────
log.info(f"Querying devices for hostname pattern: {hostname!r}")
try:
    aid_response = falcon.query_devices_by_filter(filter=f"hostname:'{hostname}*'")
    check_api_response(aid_response, context="query_devices_by_filter")
    aid = get_resources(aid_response, context="query_devices_by_filter")
except RuntimeError as e:
    log.error(f"Failed to find device: {e}")
    sys.exit(1)

# ── Get device details ────────────────────────────────────────────────────────
log.info(f"Fetching device details for AID: {aid}")
try:
    device_response = falcon.get_device_details_v2(ids=aid)
    check_api_response(device_response, context="get_device_details_v2")
    device = get_resources(device_response, context="get_device_details_v2")
    device_id = device.get("device_id")
    if not device_id:
        raise RuntimeError("device_id missing from device details response.")
except RuntimeError as e:
    log.error(f"Failed to get device details: {e}")
    sys.exit(1)

# ── Init RTR session ──────────────────────────────────────────────────────────
log.info(f"Initiating RTR session for device: {device_id}")
rtr = RealTimeResponse(client_id=RCLIENT_ID, client_secret=RCLIENT_SECRET)
try:
    session_response = rtr.init_session(device_id=device_id)
    check_api_response(session_response, context="init_session")
    session = get_resources(session_response, context="init_session")
    session_id = session.get("session_id")
    if not session_id:
        raise RuntimeError("session_id missing from init_session response.")
except RuntimeError as e:
    log.error(f"Failed to initialise RTR session: {e}")
    sys.exit(1)

log.info(f"RTR session established: {session_id}")

# ── RTR Admin commands ────────────────────────────────────────────────────────
rtradm = RealTimeResponseAdmin(client_id=RCLIENT_ID, client_secret=RCLIENT_SECRET)

# Put BrowsingHistoryView.exe on host
log.info("Putting BrowsingHistoryView.exe on host...")
try:
    put_response = rtradm.execute_admin_command(
        base_command="put",
        command_string="put 'BrowsingHistoryView.exe'",
        session_id=session_id,
    )
    check_api_response(put_response, context="execute_admin_command [put]")
except RuntimeError as e:
    log.error(f"Failed to put executable: {e}")
    sys.exit(1)

# Run browser history script
log.info("Running 'Pull Browser History' script on host...")
try:
    script_response = rtradm.execute_admin_command(
        base_command="runscript",
        command_string="runscript -CloudFile='Pull Browser History' -CommandLine=",
        session_id=session_id,
    )
    check_api_response(script_response, context="execute_admin_command [runscript]")
except RuntimeError as e:
    log.error(f"Failed to run browser history script: {e}")
    sys.exit(1)

# Run ls command
log.info("Running ls command on host...")
try:
    ls_response = rtradm.execute_admin_command(
        base_command="ls",
        command_string="ls",
        session_id=session_id,
    )
    check_api_response(ls_response, context="execute_admin_command [ls]")
    ls_cloud_request_id = get_resources(ls_response, context="execute_admin_command [ls]").get("cloud_request_id")
    if not ls_cloud_request_id:
        raise RuntimeError("cloud_request_id missing from ls response.")
except RuntimeError as e:
    log.error(f"Failed to run ls command: {e}")
    sys.exit(1)

time.sleep(10)

# Check ls command output
try:
    ls_status = rtr.check_command_status(cloud_request_id=ls_cloud_request_id)
    check_api_response(ls_status, context="check_command_status [ls]")
    ls_result = get_resources(ls_status, context="check_command_status [ls]")
    log.info(f"ls result: {ls_result}")
except RuntimeError as e:
    log.error(f"Failed to check ls command status: {e}")
    sys.exit(1)

# ── Get history.csv ───────────────────────────────────────────────────────────
MAX_GET_RETRIES = 3
POLL_INTERVAL_SECONDS = 20
MAX_POLL_ATTEMPTS = 15


def initiate_get_command(rtr_client, sid):
    """Issues a 'get' command for history.csv and returns the cloud_request_id."""
    resp = rtr_client.execute_active_responder_command(
        base_command="get",
        command_string="get 'C:\\history.csv'",
        session_id=sid,
        timeout="1000",
    )
    check_api_response(resp, context="execute_active_responder_command [get]")
    cloud_req_id = get_resources(resp, context="execute_active_responder_command [get]").get("cloud_request_id")
    if not cloud_req_id:
        raise RuntimeError("cloud_request_id missing from get command response.")
    return cloud_req_id


log.info("Issuing get command for C:\\history.csv ...")
try:
    get_cloud_request_id = initiate_get_command(rtr, session_id)
except RuntimeError as e:
    log.error(f"Failed to issue get command: {e}")
    sys.exit(1)

# Poll until complete, with retry on stderr
waiting = True
poll_attempts = 0
get_retries = 0

while waiting:
    if poll_attempts >= MAX_POLL_ATTEMPTS:
        log.error(f"Timed out waiting for history.csv after {MAX_POLL_ATTEMPTS} attempts.")
        sys.exit(1)

    log.info(f"Waiting for history.csv... (attempt {poll_attempts + 1}/{MAX_POLL_ATTEMPTS})")
    time.sleep(POLL_INTERVAL_SECONDS)
    poll_attempts += 1

    try:
        get_status = rtr.check_active_responder_command_status(cloud_request_id=get_cloud_request_id)
        check_api_response(get_status, context="check_active_responder_command_status [get]")
        get_result = get_resources(get_status, context="check_active_responder_command_status [get]")
    except RuntimeError as e:
        log.warning(f"Error checking get command status: {e}. Retrying...")
        continue

    is_complete = get_result.get("complete", False)
    stdout = get_result.get("stdout", "")
    stderr = get_result.get("stderr", "")

    if not is_complete:
        continue

    if stderr:
        log.warning(f"get command returned stderr: {stderr}")
        if get_retries >= MAX_GET_RETRIES:
            log.error(f"Exceeded max retries ({MAX_GET_RETRIES}) for get command due to repeated stderr.")
            sys.exit(1)
        log.info(f"Retrying get command (retry {get_retries + 1}/{MAX_GET_RETRIES})...")
        get_retries += 1
        try:
            get_cloud_request_id = initiate_get_command(rtr, session_id)
        except RuntimeError as e:
            log.error(f"Failed to re-issue get command: {e}")
            sys.exit(1)
        poll_attempts = 0
        continue

    if stdout:
        log.info("history.csv retrieved successfully.")
        waiting = False
    else:
        log.warning("get command complete but stdout is empty. Continuing to wait...")

# ── List and download file ────────────────────────────────────────────────────
log.info("Listing files available for download...")
try:
    file_list_response = rtr.list_files_v2(session_id)
    check_api_response(file_list_response, context="list_files_v2")
    file_list = file_list_response.get("body", {}).get("resources")
    if not file_list:
        raise RuntimeError("No files found in list_files_v2 response.")
except RuntimeError as e:
    log.error(f"Failed to list files: {e}")
    sys.exit(1)

log.info(f"Files available: {[f.get('name', 'unknown') for f in file_list]}")

save_file = "webhistory.7z"
downloaded = False

for i, file_entry in enumerate(file_list):
    sha256 = file_entry.get("sha256")
    if not sha256:
        log.warning(f"File at index {i} has no sha256, skipping.")
        continue

    log.info(f"Downloading file with sha256: {sha256}")
    try:
        file_extract = rtr.get_extracted_file_contents(
            session_id=session_id,
            filename="\\Device\\HarddiskVolume3\\history.csv",
            sha256=sha256,
        )
        # get_extracted_file_contents returns raw bytes, not a dict
        if not isinstance(file_extract, bytes) or len(file_extract) == 0:
            raise RuntimeError(f"Extracted file content is empty or not bytes for sha256={sha256}.")

        with open(save_file, 'wb') as saved:
            saved.write(file_extract)
        log.info(f"File saved to {save_file}")
        downloaded = True
        break

    except (RuntimeError, OSError) as e:
        log.error(f"Failed to download or save file (sha256={sha256}): {e}")
        continue

if not downloaded:
    log.error("No valid file was downloaded. Exiting.")
    sys.exit(1)

log.info("Done.")
