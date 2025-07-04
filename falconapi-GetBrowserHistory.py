
import os
import time
import re
# Requires Crowdstrike falcon and falconpy python package

from falconpy import RealTimeResponse, RealTimeResponseAdmin, Hosts

# Do not hardcode API credentials!

RCLIENT_ID = os.environ['RCLIENTID']
RCLIENT_SECRET=os.environ['RCLIENT_SECRET']

CLIENT_ID = os.environ['CLIENT_ID']
CLIENT_SECRET=os.environ['CLIENT_SECRET']

falcon = Hosts(client_id=CLIENT_ID,
               client_secret=CLIENT_SECRET
               )

# Must be valid hostname with sensor - case insensitivels
gethostname = input("Please enter hostname: ")
hostname = gethostname

aid = falcon.query_devices_by_filter(
                    filter=f"hostname:'{hostname}*'"
                    )["body"]["resources"][0]

id_list = aid  # Can also pass a list here: ['ID1', 'ID2', 'ID3']

newresponse = falcon.get_device_details_v2(ids=id_list)

# Iterate through keys
# print(newresponse["body"]["resources"][0])
# print(type(newresponse["body"]["resources"][0]))
# print(newresponse["body"]["resources"][0]["device_id"])

device_id = newresponse["body"]["resources"][0]["device_id"]

# Do not hardcode API credentials!
rtr = RealTimeResponse(client_id=RCLIENT_ID,
                               client_secret=RCLIENT_SECRET
                               )

response = rtr.init_session(device_id=device_id,)

# print(response)
# print(response["body"]["resources"][0]["session_id"])

session_id = response["body"]["resources"][0]["session_id"]

# Do not hardcode API credentials!
rtradm = RealTimeResponseAdmin(client_id=RCLIENT_ID,
                               client_secret=RCLIENT_SECRET
                               )
# Put Browsing History executable on host
putreq = rtradm.execute_admin_command(base_command="put",
                                  command_string=f"put 'BrowsingHistoryView.exe'",
                                  session_id=session_id,
                                  )
# print("Output of putreq==>")
# print(putreq)

# Put Browsing History executable on host
rscript = rtradm.execute_admin_command(base_command="runscript",
                                  command_string=f"runscript -CloudFile='Pull Browser History'  -CommandLine=",
                                  session_id=session_id 
                                  )
# print("Output of rscript==>")
# print(rscript)

# Run ls command on host
lsscript = rtradm.execute_admin_command(base_command="ls",
                                  command_string=f"ls",
                                  session_id=session_id,
                                  )
# Giving time for cloud request to generate

time.sleep(10)

# print("Output of lsscript")
# print(lsscript)

# print(type(lsscript))
# print(lsscript["body"]["resources"][0]["cloud_request_id"])

# Check the ls command output
lsresponse = rtr.check_command_status(cloud_request_id=lsscript["body"]["resources"][0]["cloud_request_id"])
print(lsresponse)
print(type(response))
print(lsresponse["body"]["resources"][0])


# Get the history.csv file (user browsing history)
gresponse = rtr.execute_active_responder_command(base_command="get",
                                  command_string=f"get 'C:\\history.csv'",
                                  session_id=session_id,
                                  timeout="1000"
                                  )
getresponse = rtr.check_active_responder_command_status(cloud_request_id=gresponse["body"]["resources"][0]["cloud_request_id"])
print(getresponse)
print(getresponse["body"]["resources"][0])

waiting = True
while waiting:
    print("Waiting for history.csv file...")
    time.sleep(20)
    getresponse = rtr.check_active_responder_command_status(cloud_request_id=gresponse["body"]["resources"][0]["cloud_request_id"])
    print(getresponse)
    if getresponse["body"]["resources"][0]["complete"] and getresponse["body"]["resources"][0]["stdout"] or getresponse["body"]["resources"][0]["stderr"]: 
            if getresponse["body"]["resources"][0]["stderr"]:
                gresponse = rtr.execute_active_responder_command(base_command="get",
                                  command_string=f"get 'C:\\history.csv'",
                                  session_id=session_id,
                                  timeout="1000"
                                  )
                getresponse = rtr.check_active_responder_command_status(cloud_request_id=gresponse["body"]["resources"][0]["cloud_request_id"])
                if getresponse["body"]["resources"][0]["complete"] and getresponse["body"]["resources"][0]["stdout"]:
                    waiting = False
                waiting = True
            if getresponse["body"]["resources"][0]["complete"] and getresponse["body"]["resources"][0]["stdout"]:
                waiting = False

# Will work on implemem=nting more robust error checking.
# waiting = True
# while waiting:
#     print("Waiting for history.csv file...")
#     getresponse = rtr.check_command_status(cloud_request_id=gresponse["body"]["resources"][0]["cloud_request_id"])
#     if getresponse["body"]["resources"][0]["complete"] and (getresponse["body"]["resources"][0]["stdout"] or getresponse["body"]["resources"][0]["stderr"]):
#             if getresponse["body"]["resources"][0]["stderr"]:
#                 print("This is stderr: ", getresponse["body"]["resources"][0]["stderr"])
#                 if getresponse["body"]["resources"][0]["stderr"]:
#                     raise SystemExit(getresponse["body"]["resources"][0]["stderr"])
#             waiting = False
# Get files available for download

file_list = rtr.list_files_v2(session_id)["body"]["resources"]
print(type(file_list))
print(file_list)
for key in file_list[0]:
    print(key)

# Loop through files and obtain correct sha256 hash
for i in range(len(file_list)):
    print(file_list[i]["sha256"])
    if file_list[i]["sha256"] != None:

        print(file_list[i]["sha256"])
        save_file = "webhistory.7z"

        file_extract = rtr.get_extracted_file_contents(session_id=session_id,
                                                    filename="\\Device\\HarddiskVolume3\\history.csv",
                                                    sha256=file_list[i]["sha256"]
                                                    )
        # Extract file to current directory
        with open(save_file, 'wb') as saved:
            saved.write(file_extract)
